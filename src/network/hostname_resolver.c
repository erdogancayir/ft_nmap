#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>

char *reverse_dns_lookup(const char *ip_addr) {
    struct sockaddr_in sa;
    char host[NI_MAXHOST];

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip_addr, &sa.sin_addr);

    int res = getnameinfo((struct sockaddr *)&sa, sizeof(sa),
                          host, sizeof(host),
                          NULL, 0, NI_NAMEREQD);

    if (res != 0) {
        return strdup("Unknown");
    }

    return strdup(host);
}
