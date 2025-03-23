#ifndef SCAN_RESULT_H
#define SCAN_RESULT_H

#include "scan_config.h"

typedef enum { STATE_UNKNOWN, STATE_OPEN, STATE_CLOSED, STATE_FILTERED } t_state;

typedef struct {
    int port;
    int src_port;
    t_state state[MAX_SCAN_TYPES];
} t_scan_result;

#endif