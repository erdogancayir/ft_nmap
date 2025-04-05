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

void handle_icmp_packet(const u_char *packet, int ip_header_len, t_shared_results *results, const char *src_ip) {
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