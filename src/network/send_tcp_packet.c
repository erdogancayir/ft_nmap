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

void send_tcp_packet(const char *src_ip, const char *dst_ip, int src_port, int dst_port, uint8_t flags) {
    char packet[4096];
    memset(packet, 0, sizeof(packet));

    struct ip *ip_hdr = (struct ip *)packet;
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ip));

    // Fill TCP header
    tcp_hdr->th_sport = htons(src_port);
    tcp_hdr->th_dport = htons(dst_port);
    tcp_hdr->th_seq = htonl(rand());
    tcp_hdr->th_ack = 0;
    tcp_hdr->th_off = 5;  // Header size = 20 bytes
    tcp_hdr->th_flags = flags;
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

    // Log IP Header details
    DEBUG_PRINT("\n=== IP Header ===\n");
    DEBUG_PRINT("Version: %d\n", ip_hdr->ip_v);
    DEBUG_PRINT("Header Length: %d bytes\n", ip_hdr->ip_hl * 4);
    DEBUG_PRINT("Type of Service: %d\n", ip_hdr->ip_tos);
    DEBUG_PRINT("Total Length: %d bytes\n", ntohs(ip_hdr->ip_len));
    DEBUG_PRINT("Identification: %d\n", ntohs(ip_hdr->ip_id));
    DEBUG_PRINT("Time To Live: %d\n", ip_hdr->ip_ttl);
    DEBUG_PRINT("Protocol: %d (TCP)\n", ip_hdr->ip_p);
    DEBUG_PRINT("Checksum: 0x%04x\n", ntohs(ip_hdr->ip_sum));
    DEBUG_PRINT("Source IP: %s\n", src_ip);
    DEBUG_PRINT("Destination IP: %s\n", dst_ip);

    // Log TCP Header details
    DEBUG_PRINT("\n=== TCP Header ===\n");
    DEBUG_PRINT("Source Port: %d\n", ntohs(tcp_hdr->th_sport));
    DEBUG_PRINT("Destination Port: %d\n", ntohs(tcp_hdr->th_dport));
    DEBUG_PRINT("Sequence Number: %u\n", ntohl(tcp_hdr->th_seq));
    DEBUG_PRINT("Acknowledgment Number: %u\n", ntohl(tcp_hdr->th_ack));
    DEBUG_PRINT("Data Offset: %d bytes\n", tcp_hdr->th_off * 4);
    DEBUG_PRINT("Window Size: %d\n", ntohs(tcp_hdr->th_win));
    DEBUG_PRINT("Checksum: 0x%04x\n", ntohs(tcp_hdr->th_sum));
    DEBUG_PRINT("Urgent Pointer: %d\n", ntohs(tcp_hdr->th_urp));
    DEBUG_PRINT("Flags: 0x%02x (", tcp_hdr->th_flags);
    if (tcp_hdr->th_flags & TH_FIN) DEBUG_PRINT("FIN ");
    if (tcp_hdr->th_flags & TH_SYN) DEBUG_PRINT("SYN ");
    if (tcp_hdr->th_flags & TH_RST) DEBUG_PRINT("RST ");
    if (tcp_hdr->th_flags & TH_PUSH) DEBUG_PRINT("PSH ");
    if (tcp_hdr->th_flags & TH_ACK) DEBUG_PRINT("ACK ");
    if (tcp_hdr->th_flags & TH_URG) DEBUG_PRINT("URG ");
    DEBUG_PRINT(")\n");
    DEBUG_PRINT("==================\n\n");

    if (sendto(sock, packet, sizeof(struct ip) + sizeof(struct tcphdr), 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto");
    }

    close(sock);
}