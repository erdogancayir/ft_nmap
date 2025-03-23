#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdio.h>

unsigned short checksum_tcp(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    unsigned short result;

    // 16-bit kelimeleri topla
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    // Eğer kalan tek bir byte varsa (tek sayıda byte durumunda)
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    // 32-bit toplamı 16-bit’e indir
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    result = (unsigned short)~sum;
    return result;
}

void send_tcp_packet(const char *src_ip, const char *dst_ip, int src_port, int dst_port, unsigned char flags) {
    char packet[4096] = {0};

    struct ip *ip_hdr = (struct ip *)packet;
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ip));

    // IP header (POSIX-style)
    ip_hdr->ip_hl = 5;  // 5 * 4 = 20 byte
    ip_hdr->ip_v = 4;   // IPv4
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    ip_hdr->ip_id = htons(rand() % 65535);
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = IPPROTO_TCP;
    ip_hdr->ip_src.s_addr = inet_addr(src_ip);
    ip_hdr->ip_dst.s_addr = inet_addr(dst_ip);
    ip_hdr->ip_sum = checksum_tcp((unsigned short *)ip_hdr, sizeof(struct ip));

    // TCP header
    tcp_hdr->th_sport = htons(src_port);
    tcp_hdr->th_dport = htons(dst_port);
    tcp_hdr->th_seq = htonl(rand());
    tcp_hdr->th_ack = 0;
    tcp_hdr->th_off = 5;  // header size = 5 * 4 = 20 byte
    tcp_hdr->th_flags = flags;
    tcp_hdr->th_win = htons(65535);
    tcp_hdr->th_sum = 0;

    // TCP pseudo-header checksum için
    struct pseudo_header {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t protocol;
        uint16_t len;
    } psh;

    psh.src = ip_hdr->ip_src.s_addr;
    psh.dst = ip_hdr->ip_dst.s_addr;
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.len = htons(sizeof(struct tcphdr));

    char pseudo[1024];
    memcpy(pseudo, &psh, sizeof(psh));
    memcpy(pseudo + sizeof(psh), tcp_hdr, sizeof(struct tcphdr));
    tcp_hdr->th_sum = checksum_tcp((unsigned short *)pseudo, sizeof(psh) + sizeof(struct tcphdr));

    // Raw socket oluştur
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return;
    }

    // IP başlığını biz yazdık → Kernel'e söyle
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = ip_hdr->ip_dst.s_addr;

    if (sendto(sock, packet, sizeof(struct ip) + sizeof(struct tcphdr), 0,
               (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        perror("sendto");
    }

    close(sock);
}
