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
 * Extracts the scan type from the given source port (our own assigned src_port).
 *
 * When creating jobs, each scan type was assigned a unique source port using:
 *   src_port = PORT_SCAN_BASE + (i * scan_type_count + j)
 * 
 * This function reverses that mapping to recover the scan type index `j`:
 *   scan_type = index % scan_type_count
 * 
 * @param src_port         The source port that we sent the scan from.
 * @param scan_type_count  Total number of scan types used in this run.
 * @return                 Index of scan type (0 to scan_type_count-1), or -1 if invalid.
 */
int extract_scan_type_from_dst_port(int src_port, int scan_type_count) {
    if (src_port < PORT_SCAN_BASE) return -1; // Invalid source port (not assigned by scanner)

    int index = src_port - PORT_SCAN_BASE;

    return index % scan_type_count; // Returns scan type index
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