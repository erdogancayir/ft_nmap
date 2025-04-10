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

/**
 * Extracts the scan job index from a given source port.
 *
 * During job creation, each scan job (combination of target IP, port, and scan type)
 * was assigned a unique source port using the formula:
 *     src_port = PORT_SCAN_BASE + job_index
 *
 * This function reverses that mapping to recover the original job index:
 *     job_index = src_port - PORT_SCAN_BASE
 *
 * The job index can then be used to map back to the scan type and other job metadata.
 */
int extract_scan_index_from_src_port(int src_port) {
    if (src_port < PORT_SCAN_BASE) return -1;
    return src_port - PORT_SCAN_BASE;
}

/**
 * Callback function invoked by libpcap for each captured packet.
 *
 * It identifies the protocol (TCP, UDP, ICMP), extracts source IP,
 * and delegates further processing to the appropriate handler.
 *
 * Also increments the shared response counter under mutex protection.
 *
 * @param args     Pointer to shared results (cast from void*)
 * @param header   PCAP packet header metadata (unused here)
 * @param packet   Pointer to the actual captured packet bytes
 */
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)header; // Currently unused

    t_shared_results *results = (t_shared_results *)args;

    // Update response counter in a thread-safe manner
    pthread_mutex_lock(&results->mutex);
    results->response_count++;
    pthread_mutex_unlock(&results->mutex);

    if (!packet)
        return;

    // Parse IP header
    const struct ip *ip_header = (const struct ip *)(packet + ETHERNET_HDR_LEN);
    if (ip_header->ip_v != 4)
        return; // Only handle IPv4 packets

    int ip_header_len = ip_header->ip_hl * 4;
    uint8_t protocol = ip_header->ip_p;
    const char *src_ip = inet_ntoa(ip_header->ip_src);

    // Dispatch to protocol-specific handler
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