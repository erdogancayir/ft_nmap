#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "scan_config.h"
#include "ft_nmap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_IPS 1024
#define MAX_LINE_LENGTH 256

void clean_exit(t_scan_config *config, const char *message) {
    if (message)
        fprintf(stderr, "%s\n", message);

    free_config(config);
    exit(EXIT_FAILURE);
}

void print_help() {
    printf("Usage: ./ft_nmap [OPTIONS]\n");
    printf("  --help               Show this help message\n");
    printf("  --ip <address>       Target IP address\n");
    printf("  --file <file>        File containing IPs to scan\n");
    printf("  --ports <list>       Ports to scan (e.g. 22,80 or 20-25)\n");
    printf("  --scan <types>       Scan types: SYN,NULL,FIN,XMAS,ACK,UDP\n");
    printf("  --speedup <number>   Number of threads (default 0, max 250)\n");
    exit(0);
}

// basic port parse (örn: 22,80,1000-1002)
int parse_ports(const char *input, int *ports, t_scan_config *config) {
    char buffer[512];
    strncpy(buffer, input, sizeof(buffer));
    buffer[sizeof(buffer)-1] = '\0';

    char *token = strtok(buffer, ",");
    int count = 0;

    while (token) {
        char *dash = strchr(token, '-');
        if (dash) {
            *dash = '\0';
            int start = atoi(token);
            int end = atoi(dash + 1);
            if (start <= 0 || end <= 0 || start > end) {
                clean_exit(config, "❌ Invalid port range");
            }
            for (int i = start; i <= end; i++) {
                if (count >= MAX_PORTS) {
                    clean_exit(config, "❌ Too many ports. Maximum is 1024.");
                }
                ports[count++] = i;
            }
        } else {
            int port = atoi(token);
            if (port <= 0) {
                clean_exit(config, "❌ Invalid port");
            }
            if (count >= MAX_PORTS) {
                clean_exit(config, "❌ Too many ports. Maximum is 1024.");
            }
            ports[count++] = port;
        }
        token = strtok(NULL, ",");
    }

    return count;
}

// Scan tiplerini parse et
int parse_scan_types(const char *input, scan_type *scans, t_scan_config *config) {
    char buffer[128];
    strncpy(buffer, input, sizeof(buffer));
    buffer[sizeof(buffer)-1] = '\0';

    char *token = strtok(buffer, ",");
    int count = 0;
    bool has_invalid = false;

    while (token && count < MAX_SCAN_TYPES) {
        if (strcmp(token, "SYN") == 0) scans[count++] = SCAN_SYN;
        else if (strcmp(token, "NULL") == 0) scans[count++] = SCAN_NULL;
        else if (strcmp(token, "FIN") == 0) scans[count++] = SCAN_FIN;
        else if (strcmp(token, "XMAS") == 0) scans[count++] = SCAN_XMAS;
        else if (strcmp(token, "ACK") == 0) scans[count++] = SCAN_ACK;
        else if (strcmp(token, "UDP") == 0) scans[count++] = SCAN_UDP;
        else {
            fprintf(stderr, "❌ Invalid scan type: %s\n", token);
            has_invalid = true;
        }
        token = strtok(NULL, ",");
    }

    if (has_invalid) {
        clean_exit(config, "🚫 One or more scan types are invalid. Use --help for valid options.");
    }

    return count;
}

char **fill_multiple_ip_list(const char *filename, t_scan_config *config) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        clean_exit(config, "❌ File does not exist");
    }

    char **ip_list = malloc(sizeof(char *) * MAX_IPS);
    if (!ip_list) {
        clean_exit(config, "❌ Memory allocation failed for ip_list.");
    }

    char line[MAX_LINE_LENGTH];
    int count = 0;

    while (fgets(line, sizeof(line), file) && count < MAX_IPS) {
        // clean newline characters
        line[strcspn(line, "\r\n")] = 0;

        if (strlen(line) == 0)
            continue;

        ip_list[count] = strdup(resolve_adress(line));
        if (!ip_list[count]) {
            clean_exit(config, "❌ Memory allocation failed for IP address.");
        }

        count++;
    }

    fclose(file);

    // Null-terminate diziyi (istersen)
    ip_list[count] = NULL;

    return ip_list;
}

void parse_args(int argc, char **argv, t_scan_config *config) {
    memset(config, 0, sizeof(*config));

    char *my_ip = NULL;
    char *my_iface = NULL;
    
    if (!find_source_ip_and_iface(&my_ip, &my_iface)) {
        clean_exit(config, "❌ IP and interface could not be found!");
    }

    config->my_ip = my_ip;
    config->my_interface = my_iface;
    int both_ip_and_file = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
			print_help();
			clean_exit(config, NULL);
		}
        else if (strcmp(argv[i], "--ip") == 0 && i+1 < argc)
        {
            char *resolved_ip = resolve_adress(argv[++i]);

            config->ip_list = malloc(2 * sizeof(char *)); // [0] = ip, [1] = NULL
            if (!config->ip_list) {
                clean_exit(config, "Memory allocation failed for ip_list.");
            }
            config->ip_list[0] = resolved_ip;
            config->ip_list[1] = NULL;
            both_ip_and_file++;
        }
        else if (strcmp(argv[i], "--file") == 0 && i+1 < argc)
        {
            both_ip_and_file++;
            config->ip_list = fill_multiple_ip_list(argv[++i], config);
        }
        else if (strcmp(argv[i], "--ports") == 0 && i+1 < argc)
            config->port_count = parse_ports(argv[++i], config->ports, config);
        else if (strcmp(argv[i], "--scan") == 0 && i+1 < argc)
            config->scan_count = parse_scan_types(argv[++i], config->scan_types, config);
        else if (strcmp(argv[i], "--speedup") == 0 && i+1 < argc)
        {
            config->speedup = atoi(argv[++i]);
            if (config->speedup <= 0 || config->speedup > 250) {
                clean_exit(config, "❌ Invalid --speedup value. Must be between 1 and 250.");
            }
        }
        else {
            clean_exit(config, "❌ Unknown or missing argument");
        }
    }

    if (both_ip_and_file == 0) {
        clean_exit(config, "❌ One of --ip or --file must be provided.");
    }
    
    if (both_ip_and_file == 2) {
        clean_exit(config, "❌ Only one of --ip or --file can be provided.");
    }

    if (config->scan_count == 0) {
        scan_type defaults[] = { SCAN_SYN, SCAN_NULL, SCAN_FIN, SCAN_XMAS, SCAN_ACK, SCAN_UDP };
        memcpy(config->scan_types, defaults, sizeof(defaults));
        config->scan_count = sizeof(defaults) / sizeof(scan_type);
    }

    if (config->port_count == 0) {
        for (int i = 1; i <= 1024; i++)
            config->ports[config->port_count++] = i;
    }

    if (config->speedup <= 0)
        config->speedup = 1;
    if (config->speedup > 250)
        config->speedup = 250;

    if (config->ip_list) {
        for (int i = 0; config->ip_list[i] != NULL; i++) {
            config->ip_count++;
        }
    }

    print_config(config);
}