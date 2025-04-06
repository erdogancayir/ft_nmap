#include "scan_result.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "scan_type.h"

void print_results(t_shared_results *results, double duration) {
    printf("\n==================== Scan Results ====================\n");
    printf("⏱ Scan took %.3f secs\n", duration);

    pthread_mutex_lock(&results->mutex);

    printf("\nOpen Ports:\n");
    printf("Port  Service Name (if applicable)        Scan-Type         Conclusion\n");
    printf("-----------------------------------------------------\n");

    t_scan_result *cur = results->head;
    while (cur) {
        if (strcmp(cur->status, "Open") == 0 || strcmp(cur->status, "Open|Filtered") == 0) {
            struct servent *serv = getservbyport(htons(cur->port), "tcp");
            const char *service_name = serv ? serv->s_name : "Unassigned";
            printf("%-5d %-36s %-17s %s\n", cur->port, service_name, scan_type_to_str(cur->scan_type), cur->status);
        }
        cur = cur->next;
    }

    printf("\nClosed/Filtered/Unfiltered Ports:\n");
    printf("Port  Service Name (if applicable)        Scan-Type         Conclusion\n");
    printf("-----------------------------------------------------\n");

    cur = results->head;
    while (cur) {
        if (strcmp(cur->status, "Open") != 0 && strcmp(cur->status, "Open|Filtered") != 0) {
            struct servent *serv = getservbyport(htons(cur->port), "tcp");
            const char *service_name = serv ? serv->s_name : "Unassigned";
            printf("%-5d %-36s %-17s %s\n", cur->port, service_name, scan_type_to_str(cur->scan_type), cur->status);
        }
        cur = cur->next;
    }

    pthread_mutex_unlock(&results->mutex);
    printf("======================================================\n");
}

const char *scan_type_to_str(int type) {
    switch (type) {
        case SCAN_SYN: return "SYN";
        case SCAN_NULL: return "NULL";
        case SCAN_FIN: return "FIN";
        case SCAN_XMAS: return "XMAS";
        case SCAN_ACK: return "ACK";
        case SCAN_UDP: return "UDP";
        default: return "UNKNOWN";
    }
}
