#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "ft_nmap.h"

void print_tcp_packet_debug(const struct tcphdr *tcp, const char *src_ip, int matched_port) {
    DEBUG_PRINT("\n=== TCP Packet Details ===\n");
    DEBUG_PRINT("Source IP: %s\n", src_ip);
    DEBUG_PRINT("Matched Port: %d\n", matched_port);
    DEBUG_PRINT("Flags: 0x%02x (", tcp->th_flags);
    if (tcp->th_flags & TH_SYN) DEBUG_PRINT("SYN ");
    if (tcp->th_flags & TH_ACK) DEBUG_PRINT("ACK ");
    if (tcp->th_flags & TH_RST) DEBUG_PRINT("RST ");
    if (tcp->th_flags & TH_FIN) DEBUG_PRINT("FIN ");
    if (tcp->th_flags & TH_PUSH) DEBUG_PRINT("PUSH ");
    if (tcp->th_flags & TH_URG) DEBUG_PRINT("URG ");
    DEBUG_PRINT(")\n");
    DEBUG_PRINT("=======================\n");
}

void print_packet_debug(const struct ip *ip_hdr, const struct tcphdr *tcp_hdr, const char *src_ip, const char *dst_ip) {
    // IP Header
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

    // TCP Header
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
}