#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

char *grab_banner(const char *ip, int port) {
    int sockfd;
    struct sockaddr_in addr;
    char buffer[1024] = {0};

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        return NULL;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    struct timeval timeout = {2, 0}; // 2 seconds timeout
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        return NULL;
    }

    int len = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    close(sockfd);

    if (len > 0) {
        buffer[len] = '\0';
        return strdup(buffer);
    }

    return NULL;
}
