#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "ft_nmap.h"

// ANSI color codes
#define CLR_RESET     "\x1b[0m"
#define CLR_BOLD      "\x1b[1m"
#define CLR_BLUE      "\x1b[34m"
#define CLR_GREEN     "\x1b[32m"
#define CLR_YELLOW    "\x1b[33m"
#define CLR_CYAN      "\x1b[36m"

void print_tcp_packet_debug(const struct tcphdr *tcp, const char *src_ip, int matched_port) {
    DEBUG_PRINT(CLR_BLUE "\n=== TCP Packet Details ===\n" CLR_RESET);
    DEBUG_PRINT("Source IP     : " CLR_GREEN "%s\n" CLR_RESET, src_ip);
    DEBUG_PRINT("Matched Port  : " CLR_GREEN "%d\n" CLR_RESET, matched_port);

    DEBUG_PRINT("Flags         : " CLR_YELLOW "0x%02x (" CLR_RESET, tcp->th_flags);
    if (tcp->th_flags & TH_SYN) DEBUG_PRINT(CLR_YELLOW "SYN " CLR_RESET);
    if (tcp->th_flags & TH_ACK) DEBUG_PRINT(CLR_YELLOW "ACK " CLR_RESET);
    if (tcp->th_flags & TH_RST) DEBUG_PRINT(CLR_YELLOW "RST " CLR_RESET);
    if (tcp->th_flags & TH_FIN) DEBUG_PRINT(CLR_YELLOW "FIN " CLR_RESET);
    if (tcp->th_flags & TH_PUSH) DEBUG_PRINT(CLR_YELLOW "PUSH " CLR_RESET);
    if (tcp->th_flags & TH_URG) DEBUG_PRINT(CLR_YELLOW "URG " CLR_RESET);
    DEBUG_PRINT(")\n");
    DEBUG_PRINT(CLR_BLUE "=======================\n" CLR_RESET);
}

void print_packet_debug(const struct ip *ip_hdr, const struct tcphdr *tcp_hdr, const char *src_ip, const char *dst_ip) {
    // IP Header
    DEBUG_PRINT(CLR_BLUE "\n=== IP Header ===\n" CLR_RESET);
    DEBUG_PRINT("Version        : " CLR_GREEN "%d\n" CLR_RESET, ip_hdr->ip_v);
    DEBUG_PRINT("Header Length  : " CLR_GREEN "%d bytes\n" CLR_RESET, ip_hdr->ip_hl * 4);
    DEBUG_PRINT("TOS            : " CLR_GREEN "%d\n" CLR_RESET, ip_hdr->ip_tos);
    DEBUG_PRINT("Total Length   : " CLR_GREEN "%d bytes\n" CLR_RESET, ntohs(ip_hdr->ip_len));
    DEBUG_PRINT("Identification : " CLR_GREEN "%d\n" CLR_RESET, ntohs(ip_hdr->ip_id));
    DEBUG_PRINT("TTL            : " CLR_GREEN "%d\n" CLR_RESET, ip_hdr->ip_ttl);
    DEBUG_PRINT("Protocol       : " CLR_GREEN "%d (TCP)\n" CLR_RESET, ip_hdr->ip_p);
    DEBUG_PRINT("Checksum       : " CLR_GREEN "0x%04x\n" CLR_RESET, ntohs(ip_hdr->ip_sum));
    DEBUG_PRINT("Source IP      : " CLR_CYAN "%s\n" CLR_RESET, src_ip);
    DEBUG_PRINT("Destination IP : " CLR_CYAN "%s\n" CLR_RESET, dst_ip);

    // TCP Header
    DEBUG_PRINT(CLR_BLUE "\n=== TCP Header ===\n" CLR_RESET);
    DEBUG_PRINT("Source Port    : " CLR_GREEN "%d\n" CLR_RESET, ntohs(tcp_hdr->th_sport));
    DEBUG_PRINT("Destination Port: " CLR_GREEN "%d\n" CLR_RESET, ntohs(tcp_hdr->th_dport));
    DEBUG_PRINT("Seq Number     : " CLR_GREEN "%u\n" CLR_RESET, ntohl(tcp_hdr->th_seq));
    DEBUG_PRINT("Ack Number     : " CLR_GREEN "%u\n" CLR_RESET, ntohl(tcp_hdr->th_ack));
    DEBUG_PRINT("Data Offset    : " CLR_GREEN "%d bytes\n" CLR_RESET, tcp_hdr->th_off * 4);
    DEBUG_PRINT("Window Size    : " CLR_GREEN "%d\n" CLR_RESET, ntohs(tcp_hdr->th_win));
    DEBUG_PRINT("Checksum       : " CLR_GREEN "0x%04x\n" CLR_RESET, ntohs(tcp_hdr->th_sum));
    DEBUG_PRINT("Urgent Pointer : " CLR_GREEN "%d\n" CLR_RESET, ntohs(tcp_hdr->th_urp));

    DEBUG_PRINT("Flags          : " CLR_YELLOW "0x%02x (" CLR_RESET, tcp_hdr->th_flags);
    if (tcp_hdr->th_flags & TH_FIN) DEBUG_PRINT(CLR_YELLOW "FIN " CLR_RESET);
    if (tcp_hdr->th_flags & TH_SYN) DEBUG_PRINT(CLR_YELLOW "SYN " CLR_RESET);
    if (tcp_hdr->th_flags & TH_RST) DEBUG_PRINT(CLR_YELLOW "RST " CLR_RESET);
    if (tcp_hdr->th_flags & TH_PUSH) DEBUG_PRINT(CLR_YELLOW "PSH " CLR_RESET);
    if (tcp_hdr->th_flags & TH_ACK) DEBUG_PRINT(CLR_YELLOW "ACK " CLR_RESET);
    if (tcp_hdr->th_flags & TH_URG) DEBUG_PRINT(CLR_YELLOW "URG " CLR_RESET);
    DEBUG_PRINT(")\n");

    DEBUG_PRINT(CLR_BLUE "==================\n\n" CLR_RESET);
}


void print_sent_message(const char *ip, int port, const char *scan_type_str) {
    DEBUG_PRINT(CLR_CYAN "📤 Sent to " CLR_BOLD "%-15s" CLR_RESET 
           CLR_YELLOW " Port: %-5d Type: %s\n" CLR_RESET,
           ip, port, scan_type_str);
}
