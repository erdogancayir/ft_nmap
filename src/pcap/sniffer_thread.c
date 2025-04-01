#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "scan_result.h"
#include "ft_nmap.h"
#include <unistd.h>

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

     
    time_t last_packet_time = time(NULL);
    results->pcap_handle = handle;  // pcap_breakloop için lazim

    while (1) {
        int res = pcap_dispatch(handle, 10, packet_handler, (unsigned char *)results);
        break;
        
        if (res > 0) {
            DEBUG_PRINT("Captured %d packet(s).\n", res);
            last_packet_time = time(NULL);
        } else {
            time_t now = time(NULL);
            if (difftime(now, last_packet_time) >= 3) {
                DEBUG_PRINT("Timeout: No packets received in the last %d seconds.\n", 3);
                break;
            }
        }

        usleep(100000); // avoid busy loop
    }

    pcap_close(handle);
    pthread_exit(NULL);
}
