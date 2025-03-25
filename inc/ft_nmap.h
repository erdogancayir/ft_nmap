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
void handle_packet(const unsigned char *packet, struct pcap_pkthdr *header, t_shared_results *results);


#endif