#ifndef SCAN_RESULT_H
#define SCAN_RESULT_H

#include "scan_config.h"

#define INET_ADDRSTRLEN 16

typedef enum { STATE_UNKNOWN, STATE_OPEN, STATE_CLOSED, STATE_FILTERED } t_state;
struct s_scan_result;

typedef struct s_shared_results {
    struct s_scan_result *head;
    pthread_mutex_t mutex;
} t_shared_results;


typedef struct s_scan_result {
    char target_ip[INET_ADDRSTRLEN];
    int port;
    int protocol; // TCP/UDP
    int scan_type; // SCAN_UDP, SCAN_SYN, etc.
    char status[32]; // Open, Closed, Filtered, etc.
    struct s_scan_result *next;
} t_scan_result;


#endif