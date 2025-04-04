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
    DEBUG_PRINT("Selected interface: %s\n", dev);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        pthread_exit(NULL);
    }

    struct bpf_program fp;
    char filter_exp[256];
    snprintf(filter_exp, sizeof(filter_exp), "tcp and src host %s and dst host %s", results->target_ip, results->my_ip);


    DEBUG_PRINT("Applied BPF filter: %s\n", filter_exp);
    
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap filter error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        pthread_exit(NULL);
    }

    DEBUG_PRINT("%d packets to process\n", results->job_count);
    //pcap_dispatch(handle, results->job_count, packet_handler, (unsigned char *)results);

    while (true) {
	    int ret = pcap_dispatch(handle, -1, packet_handler, (unsigned char *)results);
        if (ret >= 0) {
            printf("ret dispatch %d\n", ret);
        }
        if (ret == -1) {
            DEBUG_PRINT("error:!!!!!!!!!!\n");
        }
        if (ret == -2) {
			// printf("breakloop: No packets\n");

            break ;
        }

        DEBUG_PRINT("pcap_dispatch() returned %d packets\n", ret);
    }

    pcap_close(handle);
    pthread_exit(NULL);
}
