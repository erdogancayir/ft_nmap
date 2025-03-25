
#include <net/if.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/ioctl.h>


char *find_source_ip()
{
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs failed");
        return NULL;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET)
        {
            int result = getnameinfo(
                ifa->ifa_addr,
                sizeof(struct sockaddr_in),
                host,
                NI_MAXHOST,
                NULL,
                0,
                NI_NUMERICHOST);

            if (result == 0 && strcmp(ifa->ifa_name, "lo") != 0)
            {
                char *source_ip = strdup(host);

                if (!*source_ip)
                {
                    perror("Memory allocation failed");
                    freeifaddrs(ifaddr);
                    return NULL;
                }

                freeifaddrs(ifaddr);
                
                return source_ip;
            }
        }
    }

    freeifaddrs(ifaddr);
    return NULL;
}