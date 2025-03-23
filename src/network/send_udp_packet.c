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
    const char *payload = "PING"; // 4 byte örnek veri
    int payload_size = 4;

    struct ip *ip_hdr = (struct ip *)packet;
    struct udphdr *udp_hdr = (struct udphdr *)(packet + sizeof(struct ip));
    char *data = (char *)(packet + sizeof(struct ip) + sizeof(struct udphdr));
    memcpy(data, payload, payload_size);

    // IP header
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

    // UDP header
    udp_hdr->uh_sport = htons(src_port);
    udp_hdr->uh_dport = htons(dst_port);
    udp_hdr->uh_ulen = htons(sizeof(struct udphdr) + payload_size);
    udp_hdr->uh_sum = 0; // opsiyonel, çoğu sistemde 0 kabul edilir

    // Soket oluştur
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
