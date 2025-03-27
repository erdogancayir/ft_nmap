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

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void)header; // warning'i bastırmak için

    t_shared_results *results = (t_shared_results *)args;

    const struct ip *ip_header = (struct ip *)(packet + 14);

    if (ip_header->ip_v != 4) return;

    int ip_header_len = ip_header->ip_hl * 4;
    unsigned char proto = ip_header->ip_p;
    const char *src_ip = inet_ntoa(ip_header->ip_src);

    if (proto == IPPROTO_TCP) {
        const struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ip_header_len);
        int src_port = ntohs(tcp->th_sport);
        u_char flags = tcp->th_flags;

        if (flags & TH_SYN && flags & TH_ACK) {
            add_scan_result(results, src_ip, src_port, SCAN_SYN, "Open");
        } else if (flags & TH_RST) {
            add_scan_result(results, src_ip, src_port, SCAN_SYN, "Closed");
        }
    }
    else if (proto == IPPROTO_UDP) {
        // UDP cevabı varsa => genellikle "Open|Filtered"
    }
    else if (proto == IPPROTO_ICMP) {
        // ICMP yanıtı UDP taraması sonucu olabilir
    }
}
