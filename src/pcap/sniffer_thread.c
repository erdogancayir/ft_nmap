#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "scan_result.h"
#include "ft_nmap.h"
#include <unistd.h>
#include <time.h>

void *sniffer_thread(void *arg) {
    t_shared_results *results = (t_shared_results *)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    const char *dev = results->interface;
    DEBUG_PRINT("Selected interface: %s\n", dev);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        pthread_exit(NULL);
    }

    struct bpf_program fp;
    char filter_exp[256];
    snprintf(filter_exp, 100, "((tcp) and (dst host %s))", results->target_ip);

    DEBUG_PRINT("Applied BPF filter: %s\n", filter_exp);
    
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap filter error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        pthread_exit(NULL);
    }
     
    int timeout_counter = 0;
    while (timeout_counter < 2 && results->job_count > 0) { // Adjust max wait (in iterations)
        int ret = pcap_dispatch(handle, -1, packet_handler, (unsigned char *)results);
        if (ret == 0) {
            DEBUG_PRINT("No packets received.\n");
            usleep(1000); // wait a little for new packets
            timeout_counter++;
        } else {
            DEBUG_PRINT("Received %d packets.\n", ret);
            results->job_count -= ret;
            timeout_counter = 0; // reset if packets received
        }
    }

    DEBUG_PRINT("Sniffer exiting after timeout.\n");

    pcap_close(handle);
    pthread_exit(NULL);
}