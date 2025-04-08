#ifndef TCP_H
#define TCP_H

#include <netinet/tcp.h>
#include <stdbool.h>

void send_tcp_packet(const char *src_ip, const char *dst_ip, int src_port, int dst_port, unsigned char flags, bool evade_mode);

#endif