#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include "scan_result.h"
#include "ft_nmap.h"
#include "job_queue.h"

/**
 * Handles a captured TCP packet and determines the scan result based on TCP flags.
 *
 * This function is called from the packet handler when a TCP packet is detected.
 * It extracts the relevant TCP header fields, determines the scan type used based
 * on the source port, and classifies the result (Open, Closed, Unfiltered) based
 * on the flags in the response.
 *
 * @param packet         The raw captured packet data
 * @param ip_header_len  Length of the IP header (to find TCP header offset)
 * @param results        Shared structure for storing scan results
 * @param src_ip         Source IP address from the packet (target's IP)
 */
void handle_tcp_packet(const u_char *packet, int ip_header_len, t_shared_results *results, const char *src_ip) {
    // Offset to the TCP header
    const struct tcphdr *tcp = (const struct tcphdr *)(packet + ETHERNET_HDR_LEN + ip_header_len);

    // 'src_port' = our original source port used when sending the packet
    int src_port = ntohs(tcp->th_dport); // destination port in their reply = our src port
    // 'dst_scan_port' = the target port we were scanning
    int dst_scan_port = ntohs(tcp->th_sport);

    // TCP control flags (SYN, ACK, RST, etc.)
    uint8_t flags = tcp->th_flags;

    // Print detailed debug output for visibility
    print_tcp_packet_debug(tcp, src_ip, dst_scan_port);

    // Recover the scan type we used based on our encoded src port
    int scan_index = extract_scan_index_from_src_port(src_port);
    int scan_type = results->scan_types[scan_index];

    // OS fingerprinting: look at TTL and window size
    const struct ip *ip_header = (const struct ip *)(packet + ETHERNET_HDR_LEN);
    int ttl = ip_header->ip_ttl;
    int window = ntohs(tcp->th_win);

    const char *os_guess = guess_os(ttl, window);


    // Classify result based on TCP flags
    if (flags & TH_SYN && flags & TH_ACK) {
        // SYN-ACK received → port is open (for SYN scan)
        add_scan_result(results, src_ip, dst_scan_port, scan_type, os_guess, "Open");
    } else if (flags & TH_RST) {
        // RST received → port is closed or unfiltered depending on scan type
        if (scan_type == SCAN_ACK) {
            // ACK scan: RST means "Unfiltered"
            add_scan_result(results, src_ip, dst_scan_port, scan_type, os_guess, "Unfiltered");
        } else {
            // SYN/NULL/FIN/XMAS scan: RST means "Closed"
            add_scan_result(results, src_ip, dst_scan_port, scan_type, os_guess, "Closed");
        }
    } else {
        // Received some unexpected flag combo — log it for debugging
        DEBUG_PRINT("Other TCP flags received for port %d\n", dst_scan_port);
    }
}