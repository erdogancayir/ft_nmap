#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>

/**
 * Performs a reverse DNS lookup for a given IP address.
 * 
 * @param ip_addr  The IP address as a string (e.g., "8.8.8.8")
 * @return         A newly allocated string containing the resolved hostname,
 *                 or "Unknown" if the lookup fails. Caller must free the result.
 */
char *reverse_dns_lookup(const char *ip_addr) {
    struct sockaddr_in sa;        // IPv4 socket address structure
    char host[NI_MAXHOST];        // Buffer to store the resolved hostname

    memset(&sa, 0, sizeof(sa));   // Clear the structure
    sa.sin_family = AF_INET;      // Set address family to IPv4
    inet_pton(AF_INET, ip_addr, &sa.sin_addr); // Convert IP string to binary form

    // Perform reverse DNS lookup
    int res = getnameinfo((struct sockaddr *)&sa, sizeof(sa),
                          host, sizeof(host),
                          NULL, 0, NI_NAMEREQD);

    if (res != 0) {
        // If lookup fails, return a default string
        return strdup("Unknown");
    }

    // Return the resolved hostname
    return strdup(host);
}
