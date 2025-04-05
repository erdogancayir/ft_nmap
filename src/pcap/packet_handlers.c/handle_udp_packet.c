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

void handle_udp_packet(const u_char *packet, int ip_header_len, t_shared_results *results, const char *src_ip) {
    const struct udphdr *udp = (const struct udphdr *)(packet + ETHERNET_HDR_LEN + ip_header_len);
    int dst_scan_port = ntohs(udp->uh_sport);
    int src_port = ntohs(udp->uh_dport);

    int scan_type = extract_scan_type_from_dst_port(src_port, results->scan_type_count);

    add_scan_result(results, src_ip, dst_scan_port, scan_type, "Open|Filtered");
}