#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "scan_result.h"
#include "ft_nmap.h"

void *sniffer_thread(void *arg) {
    t_shared_results *results = (t_shared_results *)arg;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // 1. Interface seç
    const char *dev = results->interface;
    DEBUG_PRINT("Selected interface: %s\n", dev);

    // 2. Pcap canlı dinleyici başlat
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        pthread_exit(NULL);
    }

    // 3. Filtre oluştur (tcp, udp ve icmp paketleri)
    struct bpf_program fp;
    char filter_exp[256];
    // snprintf(filter_exp, sizeof(filter_exp),
    //          "(tcp and src host %s and (tcp[tcpflags] & (tcp-syn|tcp-ack|tcp-rst) != 0)) or "
    //          "(icmp and src host %s) or "
    //          "(udp and src host %s)",
    //          results->target_ip, results->target_ip, results->target_ip);
    snprintf(filter_exp, 100, "((tcp) and (dst host %s))", results->target_ip);

    DEBUG_PRINT("Applied BPF filter: %s\n", filter_exp);
    
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap filter error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        pthread_exit(NULL);
    }

    // 4. Paketleri dinlemeye başla
    while (!stop_sniffer) {
        pcap_dispatch(handle, 10, packet_handler, (unsigned char *)results);
    }

    DEBUG_PRINT("Sniffer thread stopped.\n");
    
    pcap_close(handle);
    pthread_exit(NULL);
}
