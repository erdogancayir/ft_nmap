#ifndef SCAN_RESULT_H
#define SCAN_RESULT_H

#include "scan_config.h"
#include <pthread.h>
#include <pcap.h>

#define INET_ADDRSTRLEN 16

typedef enum { STATE_UNKNOWN, STATE_OPEN, STATE_CLOSED, STATE_FILTERED } t_state;

typedef struct s_scan_result {
    char *ip;
    int port;
    scan_type scan_type; // SYN, NULL, vs.
    char *status;  // Open, Filtered, Closed
    char *hostname;
    char *version;
    char *os_guess; // OS guess based on TTL and window size

    struct s_scan_result *next;
} t_scan_result;

typedef struct s_shared_results {
    t_scan_result *head;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    char *interface;
    char *target_ip;
    char *my_ip;
    int job_count;
    int scan_type_count;
    int ip_count;

    int response_count;
    scan_type scan_types[MAX_SCAN_TYPES];

} t_shared_results;

void free_scan_result(t_scan_result *result);
t_shared_results *init_shared_results(t_scan_config *config, int queue_size);

#endif
