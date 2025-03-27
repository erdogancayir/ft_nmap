#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pcap.h>
#include "scan_result.h"

char *find_source_ip();
void *pcap_listener_thread(void *arg);
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void *sniffer_thread(void *arg);
void add_scan_result(t_shared_results *results, const char *ip, int port, int scan_type, const char *status);
void print_results(t_shared_results *results);


#endif