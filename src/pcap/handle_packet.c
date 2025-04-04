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

// Fallback for systems without <netinet/ip_icmp.h>
#if !defined(__linux__) && !defined(ICMPHDR_DEFINED)
#define ICMPHDR_DEFINED
struct icmphdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    union {
        struct { uint16_t id, sequence; } echo;
        uint32_t gateway;
        struct { uint16_t unused, mtu; } frag;
    } un;
};
#endif

static int extract_scan_type_from_dst_port(int dst_port) {
    return (dst_port - PORT_SCAN_BASE) / SCAN_TYPE_OFFSET;
}

static void handle_tcp_packet(const u_char *packet, int ip_header_len, t_shared_results *results, const char *src_ip) {
    const struct tcphdr *tcp = (const struct tcphdr *)(packet + ETHERNET_HDR_LEN + ip_header_len);

    int src_port = ntohs(tcp->th_dport);  // Hedefteki gerçek port (örneğin 22)
    int dst_port = ntohs(tcp->th_sport);  // Bizim tarafımızdan atanmış port (örneğin 40000)
    uint8_t flags = tcp->th_flags;

    print_tcp_packet_debug(tcp, src_ip, dst_port);

    int scan_type = extract_scan_type_from_dst_port(src_port);  // ✅ FIX
    int source_port = PORT_SCAN_BASE - src_port;

    if (flags & TH_SYN && flags & TH_ACK) {
        add_scan_result(results, src_ip, source_port, scan_type, "Open");
    } else if (flags & TH_RST) {
        if (scan_type == SCAN_ACK)
            add_scan_result(results, src_ip, source_port, scan_type, "Unfiltered");
        else
            add_scan_result(results, src_ip, source_port, scan_type, "Closed");
    } else {
        DEBUG_PRINT("Other TCP flags received for port %d\n", source_port);
    }
}

static void handle_udp_packet(const u_char *packet, int ip_header_len, t_shared_results *results, const char *src_ip) {
    const struct udphdr *udp = (const struct udphdr *)(packet + ETHERNET_HDR_LEN + ip_header_len);
    int src_port = ntohs(udp->uh_sport);
    int dst_port = ntohs(udp->uh_dport);

    int scan_type = extract_scan_type_from_dst_port(dst_port);

    add_scan_result(results, src_ip, src_port, scan_type, "Open|Filtered");
}

static void handle_icmp_packet(const u_char *packet, int ip_header_len, t_shared_results *results, const char *src_ip) {
    const struct icmphdr *icmp = (const struct icmphdr *)(packet + ETHERNET_HDR_LEN + ip_header_len);

    if (icmp->type == 3 && icmp->code == 3) {
        const struct ip *inner_ip = (const struct ip *)(packet + ETHERNET_HDR_LEN + ip_header_len + 8);
        if (inner_ip->ip_p == IPPROTO_UDP) {
            int inner_ip_header_len = inner_ip->ip_hl * 4;
            const struct udphdr *inner_udp = (const struct udphdr *)((const u_char *)inner_ip + inner_ip_header_len);
            int target_port = ntohs(inner_udp->uh_dport);
            int scan_type = SCAN_UDP;

            add_scan_result(results, src_ip, target_port, scan_type, "Closed");
        }
    }
}

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)header;


    t_shared_results *results = (t_shared_results *)args;

    // Basic safety check
    if (!packet) return;

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
