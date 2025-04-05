#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include "scan_result.h"
#include "ft_nmap.h"
#include "job_queue.h"

int extract_scan_type_from_dst_port(int src_port, int scan_type_count) {
    if (src_port < PORT_SCAN_BASE) return -1; // invalid

    DEBUG_PRINT("SRC PORT: %d SCAN TYPE COUNT: %d\n", src_port, scan_type_count);
    DEBUG_PRINT("PORT SCAN BASE: %d\n", PORT_SCAN_BASE);
    int index = src_port - PORT_SCAN_BASE;
    return index % scan_type_count;
}

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)header;

    t_shared_results *results = (t_shared_results *)args;

    pthread_mutex_lock(&results->mutex);
        results->response_count++;
    pthread_mutex_unlock(&results->mutex);

    // Basic safety check
    if (!packet)
        return;

    const struct ip *ip_header = (const struct ip *)(packet + ETHERNET_HDR_LEN);
    if (ip_header->ip_v != 4) return;

    int ip_header_len = ip_header->ip_hl * 4;
    uint8_t protocol = ip_header->ip_p;
    const char *src_ip = inet_ntoa(ip_header->ip_src);

    switch (protocol) {
        case IPPROTO_TCP:
            handle_tcp_packet(packet, ip_header_len, results, src_ip);
            break;
        case IPPROTO_UDP:
            handle_udp_packet(packet, ip_header_len, results, src_ip);
            break;
        case IPPROTO_ICMP:
            handle_icmp_packet(packet, ip_header_len, results, src_ip);
            break;
        default:
            printf("Unknown protocol: %d\n", protocol);
            break;
    }
}
