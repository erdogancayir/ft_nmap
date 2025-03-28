#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h> // POSIX uyumlu ICMP tanımı varsa burada olur
#include <arpa/inet.h>
#include <net/ethernet.h>
#include "scan_result.h"
#include "ft_nmap.h"
#include "job_queue.h"

// Eğer sistemde struct icmphdr tanımı eksikse (örneğin macOS)
#if !defined(__linux__) && !defined(ICMPHDR_DEFINED)
#define ICMPHDR_DEFINED
struct icmphdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    union {
        struct {
            uint16_t id;
            uint16_t sequence;
        } echo;
        uint32_t gateway;
        struct {
            uint16_t unused;
            uint16_t mtu;
        } frag;
    } un;
};
#endif

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)header;

    t_shared_results *results = (t_shared_results *)args;
    const struct ip *ip_header = (struct ip *)(packet + 14);

    if (ip_header->ip_v != 4) return;

    int ip_header_len = ip_header->ip_hl * 4;
    u_char proto = ip_header->ip_p;
    const char *src_ip = inet_ntoa(ip_header->ip_src);

    if (proto == IPPROTO_TCP) {
        const struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ip_header_len);
        int src_port = ntohs(tcp->th_sport);
        int dst_port = ntohs(tcp->th_dport);
        u_char flags = tcp->th_flags;

        int scan_type = (dst_port - 40000) / 1000;

        if (flags & TH_SYN && flags & TH_ACK) {
            add_scan_result(results, src_ip, src_port, scan_type, "Open");
        } else if (flags & TH_RST) {
            if (scan_type == SCAN_ACK)
                add_scan_result(results, src_ip, src_port, scan_type, "Unfiltered");
            else
                add_scan_result(results, src_ip, src_port, scan_type, "Closed");
        }
    }

    else if (proto == IPPROTO_UDP) {
        const struct udphdr *udp = (struct udphdr *)(packet + 14 + ip_header_len);
        int src_port = ntohs(udp->uh_sport);
        int dst_port = ntohs(udp->uh_dport);

        int scan_type = (dst_port - 40000) / 1000;

        add_scan_result(results, src_ip, src_port, scan_type, "Open|Filtered");
    }

    else if (proto == IPPROTO_ICMP) {
        struct icmphdr *icmp = (struct icmphdr *)(packet + 14 + ip_header_len);

        if (icmp->type == 3 && icmp->code == 3) {
            const struct ip *inner_ip = (struct ip *)(packet + 14 + ip_header_len + 8);
            if (inner_ip->ip_p == IPPROTO_UDP) {
                int inner_ip_header_len = inner_ip->ip_hl * 4;
                const struct udphdr *inner_udp = (struct udphdr *)((const u_char *)inner_ip + inner_ip_header_len);
                int target_port = ntohs(inner_udp->uh_dport);
                int scan_type = SCAN_UDP;

                add_scan_result(results, src_ip, target_port, scan_type, "Closed");
            }
        }
    }
}
