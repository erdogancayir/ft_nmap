#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "scan_result.h"
#include "ft_nmap.h"
#include <stdio.h>
#include <unistd.h>

/**
 * Sniffer thread responsible for capturing response packets from the target.
 *
 * It sets up a live packet capture session using `libpcap`, applies a BPF filter
 * to limit captured traffic to only TCP packets from the target IP, and processes
 * them using a non-blocking `pcap_dispatch()` loop.
 *
 * The sniffer automatically exits if:
 *  - An error occurs
 *  - A 3-second period passes without any captured packets (inactivity timeout)
 *
 * @param arg Pointer to shared scan results (cast from void*)
 * @return NULL (thread exits via pthread_exit)
 */
void *sniffer_thread(void *arg) {
    t_shared_results *results = (t_shared_results *)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    const char *dev = results->interface;

    // Open the network interface for live capture (promiscuous mode, 100ms read timeout)
    handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        pthread_exit(NULL);
    }

    // Prepare and apply BPF filter: only capture TCP packets from target to our IP
    struct bpf_program fp;
    char filter_exp[256];
    snprintf(filter_exp, sizeof(filter_exp), "tcp and src host %s and dst host %s", results->target_ip, results->my_ip);

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap filter error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        pthread_exit(NULL);
    }

    // Set non-blocking mode so pcap_dispatch() returns immediately if no packets
    if (pcap_setnonblock(handle, 1, errbuf) == -1) {
        fprintf(stderr, "Failed to set non-blocking mode: %s\n", errbuf);
        pcap_close(handle);
        pthread_exit(NULL);
    }

    int idle_time = 0; // How long we've gone without receiving packets (ms)

    while (true) {
        // Dispatch packets to the handler; -1 = process all in buffer
        int ret = pcap_dispatch(handle, -1, packet_handler, (unsigned char *)results);

        if (results->response_count == results->job_count) {
            DEBUG_PRINT("✅ All responses received, exiting sniffer thread\n");
            break;
        }

        if (ret == -1) {
            // Error during dispatch
            fprintf(stderr, "pcap_dispatch error!\n");
            break;
        }

        if (ret == 0) {
            // No packets received this tick — sleep 1ms
            usleep(1000);
            idle_time += 1;
        } else {
            // Packet(s) received — reset inactivity timer
            idle_time = 0;
        }

        // Exit if no packets received for 3 seconds
        if (idle_time > SNIFFER_TIMEOUT_MS) {
            DEBUG_PRINT("⏱ Timeout reached: no packet for 3 seconds\n");
            break;
        }
    }

    // Cleanup and exit
    pcap_close(handle);
    pthread_exit(NULL);
}