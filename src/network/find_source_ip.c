#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdbool.h>

bool find_source_ip_and_iface(char **ip_out, char **iface_out) {
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs failed");
        return false;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;

        if (ifa->ifa_addr->sa_family == AF_INET &&
            (ifa->ifa_flags & IFF_UP) &&
            (ifa->ifa_flags & IFF_RUNNING) &&
            !(ifa->ifa_flags & IFF_LOOPBACK)) {

            int result = getnameinfo(
                ifa->ifa_addr,
                sizeof(struct sockaddr_in),
                host,
                NI_MAXHOST,
                NULL,
                0,
                NI_NUMERICHOST);

            if (result == 0) {
                *ip_out = strdup(host);
                *iface_out = strdup(ifa->ifa_name);
                freeifaddrs(ifaddr);
                return true;
            }
        }
    }

    freeifaddrs(ifaddr);
    return false;
}
