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
 * Handles a captured UDP packet and records it as a potential Open|Filtered result.
 *
 * In UDP scanning, the absence of an ICMP "port unreachable" error can imply that
 * a port is either open or filtered. If a UDP packet response is received, we
 * conservatively mark it as "Open|Filtered", since many services don't respond
 * to invalid or unexpected UDP probes.
 *
 * @param packet         Raw captured packet data
 * @param ip_header_len  Length of the IP header
 * @param results        Shared results structure for recording scan outcome
 * @param src_ip         IP address of the sender (target host)
 */
void handle_udp_packet(const u_char *packet, int ip_header_len, t_shared_results *results, const char *src_ip) {
    // Locate UDP header within the packet
    const struct udphdr *udp = (const struct udphdr *)(packet + ETHERNET_HDR_LEN + ip_header_len);

    // 'dst_scan_port' = the target port we were scanning
    int dst_scan_port = ntohs(udp->uh_sport);

    // 'src_port' = the source port we used (assigned from PORT_SCAN_BASE + offset)
    int src_port = ntohs(udp->uh_dport);

    // Recover the scan type from the source port encoding
    int scan_type = extract_scan_type_from_dst_port(src_port, results->scan_type_count);

    // Since UDP services often don't reply, any UDP response is interpreted as "Open|Filtered"
    add_scan_result(results, src_ip, dst_scan_port, scan_type, "Open|Filtered");
}