#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "scan_result.h"
#include "ft_nmap.h"
#include <stdio.h>
#include <unistd.h>

void *sniffer_thread(void *arg) {
    t_shared_results *results = (t_shared_results *)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    const char *dev = results->interface;
    handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        pthread_exit(NULL);
    }

    struct bpf_program fp;
    char filter_exp[256];
    snprintf(filter_exp, sizeof(filter_exp), "tcp and src host %s and dst host %s", results->target_ip, results->my_ip);

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap filter error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        pthread_exit(NULL);
    }

    // Set non-blocking mode
    if (pcap_setnonblock(handle, 1, errbuf) == -1) {
        fprintf(stderr, "Failed to set non-blocking mode: %s\n", errbuf);
        pcap_close(handle);
        pthread_exit(NULL);
    }

    int idle_time = 0;

    while (true) {
        int ret = pcap_dispatch(handle, -1, packet_handler, (unsigned char *)results);
    
        if (ret == -1) {
            fprintf(stderr, "pcap_dispatch error!\n");
            break;
        }
    
        if (ret == 0) {
            usleep(1000); // sleep 1ms
            idle_time += 1;
        } else {
            idle_time = 0; // reset on traffic
        }
    
        if (idle_time > 3000) { // 3 seconds of inactivity
            DEBUG_PRINT("⏱ Timeout reached: no packet for 3 seconds\n");
            break;
        }
    }
    
    pcap_close(handle);
    pthread_exit(NULL);
}
