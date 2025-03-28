#ifndef SCAN_RESULT_H
#define SCAN_RESULT_H

#include "scan_config.h"
#include <pthread.h>

#define INET_ADDRSTRLEN 16

typedef enum { STATE_UNKNOWN, STATE_OPEN, STATE_CLOSED, STATE_FILTERED } t_state;

typedef struct s_scan_result {
    char *ip;
    int port;
    int scan_type; // SYN, NULL, vs.
    char *status;  // Open, Filtered, Closed
    struct s_scan_result *next;
} t_scan_result;

typedef struct s_shared_results {
    t_scan_result *head;
    pthread_mutex_t mutex;
} t_shared_results;

#endif
