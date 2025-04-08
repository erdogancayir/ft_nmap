#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdint.h>
#include "ft_nmap.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

// TCP checksum includes pseudo-header
struct pseudo_header {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_length;
};

unsigned short compute_checksum(unsigned short *addr, int len) {
    unsigned long sum = 0;

    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }

    if (len == 1) {
        sum += *((unsigned char *)addr);
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void send_tcp_packet(const char *src_ip, const char *dst_ip, int src_port, int dst_port, uint8_t flags, bool evade_mode) {
    char packet[4096];
    memset(packet, 0, sizeof(packet));

    struct ip *ip_hdr = (struct ip *)packet;
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ip));

    int tcp_header_len = sizeof(struct tcphdr);
    int total_packet_len = sizeof(struct ip) + tcp_header_len;

    // If evade mode, apply TCP options
    u_char tcp_options[4] = {2, 4, 0x05, 0xb4}; // MSS = 1460

    if (evade_mode) {
        // Set custom evasion flags
        flags = TH_URG | TH_FIN | TH_PUSH;
        tcp_hdr->th_flags = flags;

        // Apply TCP options and update header size
        memcpy((u_char *)tcp_hdr + tcp_header_len, tcp_options, sizeof(tcp_options));
        tcp_header_len += sizeof(tcp_options);
        tcp_hdr->th_off = tcp_header_len >> 2;  // Header length in 32-bit words

        total_packet_len = sizeof(struct ip) + tcp_header_len;
    } else {
        tcp_hdr->th_off = sizeof(struct tcphdr) >> 2;  // No options: 20 bytes = 5 * 4
        tcp_hdr->th_flags = flags;
    }

    // Fill TCP header
    tcp_hdr->th_sport = htons(src_port);
    tcp_hdr->th_dport = htons(dst_port);
    tcp_hdr->th_seq = htonl(rand());
    tcp_hdr->th_ack = 0;
    tcp_hdr->th_win = htons(65535);
    tcp_hdr->th_sum = 0;
    tcp_hdr->th_urp = 0;

    // Create pseudo header
    struct pseudo_header psh;
    psh.src = inet_addr(src_ip);
    psh.dst = inet_addr(dst_ip);
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    // Build pseudo packet for checksum
    char pseudo_packet[1024];
    memcpy(pseudo_packet, &psh, sizeof(psh));
    memcpy(pseudo_packet + sizeof(psh), tcp_hdr, sizeof(struct tcphdr));

    tcp_hdr->th_sum = compute_checksum((unsigned short *)pseudo_packet,
                                       sizeof(psh) + sizeof(struct tcphdr));

    // Fill IP header
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    ip_hdr->ip_id = htons(rand() % 65535);
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = IPPROTO_TCP;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_src.s_addr = inet_addr(src_ip);
    ip_hdr->ip_dst.s_addr = inet_addr(dst_ip);
    ip_hdr->ip_sum = compute_checksum((unsigned short *)ip_hdr, sizeof(struct ip));

    // Create raw socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return;
    }

    int optval = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        perror("setsockopt");
        close(sock);
        return;
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = tcp_hdr->th_dport;  // Optional
    inet_pton(AF_INET, dst_ip, &dest.sin_addr);

    print_packet_debug(ip_hdr, tcp_hdr, src_ip, dst_ip);

    if (sendto(sock, packet, total_packet_len, 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto");
    }

    close(sock);
}