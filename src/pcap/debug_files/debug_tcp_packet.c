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