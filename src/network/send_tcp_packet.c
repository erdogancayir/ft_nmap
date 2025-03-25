#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdint.h>

// TCP checksum hesaplaması (pseudo-header dahil)
unsigned short checksum_tcp(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    unsigned short result;

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

    result = (unsigned short)~sum;
    return result;
}

void send_tcp_packet(const char *src_ip, const char *dst_ip, int src_port, int dst_port, unsigned char flags) {
    char packet[4096] = {0};

    struct tcphdr *tcp_hdr = (struct tcphdr *)packet;

    // TCP header
    tcp_hdr->th_sport = htons(src_port);
    tcp_hdr->th_dport = htons(dst_port);
    tcp_hdr->th_seq = htonl(rand());
    tcp_hdr->th_ack = 0;
    tcp_hdr->th_off = 5;  // header size = 5 * 4 = 20 byte
    tcp_hdr->th_flags = flags;
    tcp_hdr->th_win = htons(65535);
    tcp_hdr->th_sum = 0;
    tcp_hdr->th_urp = 0;

    // TCP pseudo-header checksum için
    struct pseudo_header {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t protocol;
        uint16_t len;
    } psh;

    psh.src = inet_addr(src_ip);
    psh.dst = inet_addr(dst_ip);
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.len = htons(sizeof(struct tcphdr));

    char pseudo[1024];
    memcpy(pseudo, &psh, sizeof(psh));
    memcpy(pseudo + sizeof(psh), tcp_hdr, sizeof(struct tcphdr));

    tcp_hdr->th_sum = checksum_tcp((unsigned short *)pseudo, sizeof(psh) + sizeof(struct tcphdr));

    // Raw TCP socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("socket");
        return;
    }

    // NOT using IP_HDRINCL – kernel will add IP header

    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port); // optional in raw socket
    inet_pton(AF_INET, dst_ip, &dst.sin_addr);

    if (sendto(sock, tcp_hdr, sizeof(struct tcphdr), 0,
               (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        perror("sendto");
    }

    close(sock);
}