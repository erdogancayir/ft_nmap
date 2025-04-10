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

    // Define TCP options for MSS (Maximum Segment Size)
    // Option kind = 2 (MSS), length = 4, value = 0x05b4 (1460 bytes)
    //0x05	MSS’in yüksek byte'ı (1460 >> 8 = 0x05)
    //0xb4	MSS’in düşük byte'ı (1460 & 0xFF = 0xb4)
    // MSS specifies the maximum amount of data (payload) that can be sent in a single TCP segment.
    u_char tcp_options[4] = {2, 4, 0x05, 0xb4}; // MSS = 1460

    if (evade_mode) {
        // Enable evasion mode by setting uncommon TCP flags
        // URG + FIN + PSH can confuse some intrusion detection systems
        flags = TH_URG | TH_FIN | TH_PUSH;
        tcp_hdr->th_flags = flags;

        // Append TCP options (e.g., MSS) right after the base TCP header
        memcpy((u_char *)tcp_hdr + tcp_header_len, tcp_options, sizeof(tcp_options));

        // Update TCP header length to include options
        tcp_header_len += sizeof(tcp_options);

        // Set data offset field (header length in 32-bit words)
        tcp_hdr->th_off = tcp_header_len >> 2;

        // Update total packet length for IP header calculation
        total_packet_len = sizeof(struct ip) + tcp_header_len;
    } else {
        // No evasion mode: standard TCP header (20 bytes)
        tcp_hdr->th_off = sizeof(struct tcphdr) >> 2;  // Default TCP header length (5 * 4 = 20 bytes)
        tcp_hdr->th_flags = flags; // Normal scan flags (e.g., SYN)
    }

    tcp_hdr->th_sport = htons(src_port);
    tcp_hdr->th_dport = htons(dst_port);
    tcp_hdr->th_seq = htonl(rand());
    tcp_hdr->th_ack = 0;
    tcp_hdr->th_win = htons(65535);
    tcp_hdr->th_sum = 0;
    tcp_hdr->th_urp = 0;

    struct pseudo_header psh;
    psh.src = inet_addr(src_ip);
    psh.dst = inet_addr(dst_ip);
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    char pseudo_packet[1024];
    memcpy(pseudo_packet, &psh, sizeof(psh));
    memcpy(pseudo_packet + sizeof(psh), tcp_hdr, sizeof(struct tcphdr));

    tcp_hdr->th_sum = compute_checksum((unsigned short *)pseudo_packet,
                                       sizeof(psh) + sizeof(struct tcphdr));

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



/*
 * TCP Header (Layer 4 - Transport Layer)
 * --------------------------------------
 * This structure defines the TCP (Transmission Control Protocol) header
 * as used in network communications, following RFC 793.
 * 
 * It is commonly used in raw socket programming and packet analysis.
 * Each field corresponds to specific parts of the TCP header.
 
    typedef struct s_tcp_header {
        uint16_t src_port;      // Source port number
        uint16_t dest_port;     // Destination port number
        uint32_t seq_num;       // Sequence number
        uint32_t ack_num;       // Acknowledgment number
        uint8_t  data_offset;   // Data offset (4 bits) + Reserved (4 bits)
        uint8_t  flags;         // TCP flags (SYN, ACK, FIN, etc.)
        uint16_t window;        // Window size (flow control)
        uint16_t checksum;      // TCP checksum (header + data + pseudo-header)
        uint16_t urgent_ptr;    // Urgent pointer (only valid if URG flag set)
    } t_tcp_header;
 */

/*
 * TCP Header Details:
 * -------------------
 * 1. src_port (16 bits):
 *    - The sender's port number.

 * 2. dest_port (16 bits):
 *    - The recipient's port number.

 * 3. seq_num (32 bits):
 *    - The sequence number of the first data byte in this segment.
 *    - Used for reliable transmission and reordering.

 * 4. ack_num (32 bits):
 *    - The acknowledgment number; valid only if the ACK flag is set.
 *    - Indicates the next expected byte.

 * 5. data_offset (8 bits total):
 *    - Top 4 bits: Header length in 32-bit words (min value is 5).
 *    - Bottom 4 bits: Reserved (should be set to 0).

 * 6. flags (8 bits):
 *    - Control flags:
 *        - FIN: 0x01
 *        - SYN: 0x02
 *        - RST: 0x04
 *        - PSH: 0x08
 *        - ACK: 0x10
 *        - URG: 0x20
 *        - ECE: 0x40
 *        - CWR: 0x80

 * 7. window (16 bits):
 *    - The size of the sender's receive window.
 *    - Used for flow control.

 * 8. checksum (16 bits):
 *    - Used to detect errors in the header and data.
 *    - Includes pseudo-header from IP layer for reliability.

 * 9. urgent_ptr (16 bits):
 *    - Points to the last urgent byte in the segment.
 *    - Only used if the URG flag is set.
 */



/*
 * IPv4 Header (Layer 3 - Network Layer)
 * -------------------------------------
 * This structure represents the IPv4 header according to RFC 791.
 * It contains metadata used by routers and hosts to deliver the packet.
 * The minimum size is 20 bytes (without options).
 *
 * Field Descriptions:
 *
 * 1. uint8_t version_ihl
 *    - Version:      The first 4 bits. Should always be 4 for IPv4.
 *    - IHL:          The last 4 bits. Header length in 32-bit words.
 *                    Minimum is 5 (i.e., 20 bytes), which means no options.
 *
 * 2. uint8_t tos
 *    - Type of Service (now called DSCP and ECN)
 *    - Used to prioritize or mark packets for QoS (Quality of Service).
 *    - Often includes bits like Delay, Throughput, Reliability, etc.
 *
 * 3. uint16_t total_length
 *    - Total size of the IP packet in bytes, including header and payload.
 *    - Maximum allowed is 65535 bytes.
 *
 * 4. uint16_t id
 *    - A unique identifier for the packet.
 *    - Used during fragmentation and reassembly.
 *
 * 5. uint16_t frag_offset
 *    - Fragmentation control.
 *    - Top 3 bits are flags:
 *        * Bit 0: Reserved (must be 0)
 *        * Bit 1: Don't Fragment (DF)
 *        * Bit 2: More Fragments (MF)
 *    - Remaining 13 bits indicate the fragment offset.
 *    - Used when a large packet is split across smaller ones.
 *
 * 6. uint8_t ttl
 *    - Time To Live.
 *    - Each router that forwards the packet decreases this value by 1.
 *    - Prevents infinite routing loops. If TTL reaches 0, packet is dropped.
 *
 * 7. uint8_t protocol
 *    - Indicates the next-layer protocol encapsulated in the payload.
 *    - Common values:
 *        * 1  = ICMP
 *        * 6  = TCP
 *        * 17 = UDP
 *
 * 8. uint16_t checksum
 *    - Checksum for the IP header only (not the payload).
 *    - Used to detect errors in header transmission.
 *
 * 9. uint32_t src_ip
 *    - Source IP address (in network byte order).
 *
 * 10. uint32_t dest_ip
 *     - Destination IP address (in network byte order).
 *
 * Notes:
 * ------
 * - This header is processed by routers to determine packet forwarding.
 * - If options are present, header size will exceed 20 bytes.
 * - Usually followed by TCP, UDP, or ICMP headers depending on the protocol field.
 */