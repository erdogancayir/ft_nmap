#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

/**
 * Attempts to connect to a TCP service and retrieve its banner.
 *
 * This function creates a TCP socket, connects to the specified IP and port,
 * and waits for the server to send a banner (typically service/version info).
 * It reads up to 1023 bytes and returns a heap-allocated copy of the banner,
 * or NULL if the connection or reception fails.
 *
 * @param ip    The target IP address as a string (e.g. "192.168.1.1")
 * @param port  The target TCP port (e.g. 80, 21)
 * @return      A malloc'd string with the banner or NULL if failed.
 */
char *grab_banner(const char *ip, int port) {
    int sockfd;
    struct sockaddr_in addr;
    char buffer[1024] = {0};

    // Create a TCP socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        return NULL;

    // Set up the sockaddr_in structure
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);                    // Convert port to network byte order
    inet_pton(AF_INET, ip, &addr.sin_addr);         // Convert IP string to binary

    // Set a 2-second timeout for recv()
    struct timeval timeout = {2, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Attempt to connect to the target IP and port
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        return NULL;
    }

    // Try to receive data (banner) from the server
    int len = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    close(sockfd); // Always close the socket after use

    if (len > 0) {
        buffer[len] = '\0';        // Null-terminate received string
        return strdup(buffer);     // Return a heap-allocated copy
    }

    return NULL; // No banner received or error
}