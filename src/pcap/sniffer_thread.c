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
    const char *dev = "eth0"; // ileride otomatikleştirilebilir

    // 2. Pcap canlı dinleyici başlat
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        pthread_exit(NULL);
    }

    // 3. Filtre oluştur (tcp, udp ve icmp paketleri)
    struct bpf_program fp;
    char filter_exp[] = "tcp or udp or icmp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap filter error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        pthread_exit(NULL);
    }

    // 4. Paketleri dinlemeye başla
    pcap_loop(handle, -1, packet_handler, (unsigned char *)results);

    pcap_close(handle);
    pthread_exit(NULL);
}
