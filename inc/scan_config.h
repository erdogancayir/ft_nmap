// creater header file
#ifndef SCAN_CONFIG_H
#define SCAN_CONFIG_H

#define MAX_PORTS 1024
#define MAX_SCAN_TYPES 6

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "scan_type.h"

typedef struct {
    char **ip_list;
    int ports[MAX_PORTS];
    int port_count;
    scan_type scan_types[MAX_SCAN_TYPES];
    int scan_count;
    int speedup;
    char *my_ip;
    char *my_interface;
    int ip_count;
} t_scan_config;


void parse_args(int argc, char **argv, t_scan_config *config);
void print_config(t_scan_config *config);

void free_config(t_scan_config *config);

#endif