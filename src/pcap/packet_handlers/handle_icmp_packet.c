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

// Fallback for systems that do not have <netinet/ip_icmp.h> or define `struct icmphdr`
// This ensures portability across different platforms (e.g., macOS, BSD)
#if !defined(__linux__) && !defined(ICMPHDR_DEFINED)
#define ICMPHDR_DEFINED
struct icmphdr {
    uint8_t type;       // ICMP message type (e.g., 3 = Destination Unreachable)
    uint8_t code;       // ICMP message subtype (e.g., code 3 = Port Unreachable)
    uint16_t checksum;  // ICMP header checksum
    union {
        struct { uint16_t id, sequence; } echo;   // Used in Echo messages
        uint32_t gateway;                         // Used in Redirect messages
        struct { uint16_t unused, mtu; } frag;    // Used in Fragmentation Needed
    } un;
};
#endif

/**
 * Handles an ICMP packet and checks for port unreachable messages,
 * which are typically used to indicate a closed UDP port.
 *
 * This is crucial for interpreting UDP scan results.
 *
 * ICMP Type 3, Code 3 = "Destination Unreachable: Port Unreachable"
 * If we see this for a UDP packet we sent, it means the port is closed.
 *
 * @param packet         Raw captured packet
 * @param ip_header_len  Length of the IP header
 * @param results        Shared structure for scan results
 * @param src_ip         Source IP (where ICMP packet came from)
 */
void handle_icmp_packet(const u_char *packet, int ip_header_len, t_shared_results *results, const char *src_ip) {
    // Point to the ICMP header within the packet
    const struct icmphdr *icmp = (const struct icmphdr *)(packet + ETHERNET_HDR_LEN + ip_header_len);

    // Check if it's "Destination Unreachable: Port Unreachable" (ICMP Type 3, Code 3)
    if (icmp->type == 3 && icmp->code == 3) {
        // The ICMP error includes the original IP header + first 8 bytes of transport header
        const struct ip *inner_ip = (const struct ip *)(packet + ETHERNET_HDR_LEN + ip_header_len + 8);

        // Ensure the original packet was a UDP packet
        if (inner_ip->ip_p == IPPROTO_UDP) {
            // Move to inner UDP header (past the embedded IP header)
            int inner_ip_header_len = inner_ip->ip_hl * 4;
            const struct udphdr *inner_udp = (const struct udphdr *)((const u_char *)inner_ip + inner_ip_header_len);

            // Extract the original target port
            int target_port = ntohs(inner_udp->uh_dport);

            // Mark this UDP port as closed
            int scan_type = SCAN_UDP;
            add_scan_result(results, src_ip, target_port, scan_type, "Closed");
        }
    }
}