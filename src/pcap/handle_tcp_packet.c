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

void handle_tcp_packet(const u_char *packet, int ip_header_len, t_shared_results *results, const char *src_ip) {
    const struct tcphdr *tcp = (const struct tcphdr *)(packet + ETHERNET_HDR_LEN + ip_header_len);

    int src_port = ntohs(tcp->th_dport); // my port
    int dst_scan_port = ntohs(tcp->th_sport);
    uint8_t flags = tcp->th_flags;

    print_tcp_packet_debug(tcp, src_ip, dst_scan_port);

    int scan_type = extract_scan_type_from_dst_port(src_port);  // ✅ FIX

    if (flags & TH_SYN && flags & TH_ACK) {
        add_scan_result(results, src_ip, dst_scan_port, scan_type, "Open");
    } else if (flags & TH_RST) {
        if (scan_type == SCAN_ACK)
            add_scan_result(results, src_ip, dst_scan_port, scan_type, "Unfiltered");
        else
            add_scan_result(results, src_ip, dst_scan_port, scan_type, "Closed");
    } else {
        DEBUG_PRINT("Other TCP flags received for port %d\n", dst_scan_port);
    }
}
