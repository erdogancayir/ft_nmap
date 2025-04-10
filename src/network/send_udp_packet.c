#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdio.h>

unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    unsigned short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (unsigned short)~sum;

    return answer;
}

void send_udp_packet(const char *src_ip, const char *dst_ip, int src_port, int dst_port) {
    char packet[4096] = {0};
    const char *payload = "PING";
    int payload_size = 4;

    struct ip *ip_hdr = (struct ip *)packet;
    struct udphdr *udp_hdr = (struct udphdr *)(packet + sizeof(struct ip));
    char *data = (char *)(packet + sizeof(struct ip) + sizeof(struct udphdr));
    memcpy(data, payload, payload_size);

    ip_hdr->ip_hl = 5;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + payload_size);
    ip_hdr->ip_id = htons(rand() % 65535);
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = IPPROTO_UDP;
    ip_hdr->ip_src.s_addr = inet_addr(src_ip);
    ip_hdr->ip_dst.s_addr = inet_addr(dst_ip);
    ip_hdr->ip_sum = checksum((unsigned short *)ip_hdr, sizeof(struct ip));

    udp_hdr->uh_sport = htons(src_port);
    udp_hdr->uh_dport = htons(dst_port);
    udp_hdr->uh_ulen = htons(sizeof(struct udphdr) + payload_size);
    udp_hdr->uh_sum = 0;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return;
    }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = ip_hdr->ip_dst.s_addr;

    if (sendto(sock, packet, ntohs(ip_hdr->ip_len), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        perror("sendto");
    }

    close(sock);
}


/*
 * UDP Header (Layer 4 - Transport Layer)
 * --------------------------------------
 * This struct defines the UDP header, which is always 8 bytes long.
 * It is used in UDP packets as the transport layer header.
 * 
 * Fields:
 * -------
 * 1. uh_sport (16 bits):
 *    - Source port number (e.g., 12345).
 *    - Indicates the port number at the sender side.
 * 
 * 2. uh_dport (16 bits):
 *    - Destination port number (e.g., 53 for DNS).
 *    - Indicates the port number at the receiver side.
 * 
 * 3. uh_ulen (16 bits):
 *    - Length of the UDP packet (header + data) in bytes.
 *    - Minimum is 8 (header only); maximum is 65535.
 * 
 * 4. uh_sum (16 bits):
 *    - UDP checksum.
 *    - Optional for IPv4. Used to verify header and payload integrity.
 *    - A value of 0 means "no checksum" in IPv4.
 * 
 * Usage:
 * ------
 * - The UDP header is placed after the IP header in an IPv4 packet.
 * - It is connectionless and does not guarantee delivery.
 * - Common protocols using UDP include DNS, DHCP, SNMP, and VoIP.

    struct udphdr {
        uint16_t uh_sport;  // Source port
        uint16_t uh_dport;  // Destination port
        uint16_t uh_ulen;   // UDP length
        uint16_t uh_sum;    // UDP checksum
    };

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