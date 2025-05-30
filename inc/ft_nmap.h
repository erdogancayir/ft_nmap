#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pcap.h>
#include "scan_result.h"
#include <signal.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "job_queue.h"

#define ETHERNET_HDR_LEN 14
#define PORT_SCAN_BASE 40000
#define SCAN_TYPE_OFFSET 1000

#define CLR_MAGENTA "\x1b[35m"
#define CLR_RESET   "\x1b[0m"

// Timeout threshold for sniffer (in milliseconds)
#define SNIFFER_TIMEOUT_MS 3000

#ifndef DEBUG
    #define DEBUG_PRINT(...) do { if (0) fprintf(stderr, __VA_ARGS__); } while (0)
#else
    #define DEBUG_PRINT(...) fprintf(stderr, __VA_ARGS__)
#endif

extern volatile sig_atomic_t stop_sniffer;


bool find_source_ip_and_iface(char **ip_out, char **iface_out);
void *pcap_listener_thread(void *arg);
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void *sniffer_thread(void *arg);
void add_scan_result(t_shared_results *results, const char *ip, int port, scan_type scan_type, const char *os_guess, const char *status);
void print_results(t_shared_results *results, double duration, t_scan_config *config);
char *resolve_adress(char *ip);
void print_tcp_packet_debug(const struct tcphdr *tcp, const char *src_ip, int matched_port);
void print_packet_debug(const struct ip *ip_hdr, const struct tcphdr *tcp_hdr, const char *src_ip, const char *dst_ip);
void print_sent_message(const char *ip, int port, const char *scan_type_str);
void print_scan_result_log(const char *ip, int port, int scan_type, const char *status);

void handle_icmp_packet(const u_char *packet, int ip_header_len, t_shared_results *results, const char *src_ip);
void handle_tcp_packet(const u_char *packet, int ip_header_len, t_shared_results *results, const char *src_ip);
void handle_udp_packet(const u_char *packet, int ip_header_len, t_shared_results *results, const char *src_ip);

int extract_scan_index_from_src_port(int dst_port);

void finalize_unanswered_jobs(t_job_queue *queue, t_shared_results *results);
char *build_bpf_filter(t_shared_results *results, int ip_count);

char *reverse_dns_lookup(const char *ip_addr);
char *grab_banner(const char *ip, int port);
const char* guess_os(int ttl, int window_size);

#endif