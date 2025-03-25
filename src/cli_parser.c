#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "scan_config.h"
#include "ft_nmap.h"

// Yardım ekranı
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

// Basit port parse (örn: 22,80,1000-1002)
int parse_ports(const char *input, int *ports) {
    char buffer[512];
    strncpy(buffer, input, sizeof(buffer));
    buffer[sizeof(buffer)-1] = '\0';

    char *token = strtok(buffer, ",");
    int count = 0;

    while (token && count < MAX_PORTS) {
        char *dash = strchr(token, '-');
        if (dash) {
            *dash = '\0';
            int start = atoi(token);
            int end = atoi(dash + 1);
            for (int i = start; i <= end && count < MAX_PORTS; i++)
                ports[count++] = i;
        } else {
            ports[count++] = atoi(token);
        }
        token = strtok(NULL, ",");
    }
    return count;
}

// Scan tiplerini parse et
int parse_scan_types(const char *input, scan_type *scans) {
    char buffer[128];
    strncpy(buffer, input, sizeof(buffer));
    buffer[sizeof(buffer)-1] = '\0';

    char *token = strtok(buffer, ",");
    int count = 0;

    while (token && count < MAX_SCAN_TYPES) {
        if (strcmp(token, "SYN") == 0) scans[count++] = SCAN_SYN;
        else if (strcmp(token, "NULL") == 0) scans[count++] = SCAN_NULL;
        else if (strcmp(token, "FIN") == 0) scans[count++] = SCAN_FIN;
        else if (strcmp(token, "XMAS") == 0) scans[count++] = SCAN_XMAS;
        else if (strcmp(token, "ACK") == 0) scans[count++] = SCAN_ACK;
        else if (strcmp(token, "UDP") == 0) scans[count++] = SCAN_UDP;
        else printf("Uyarı: geçersiz scan tipi: %s\n", token);
        token = strtok(NULL, ",");
    }

    return count;
}

void parse_args(int argc, char **argv, t_scan_config *config) {
    memset(config, 0, sizeof(*config));

    config->my_ip = find_source_ip();

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0)
            config->show_help = true;
        else if (strcmp(argv[i], "--ip") == 0 && i+1 < argc)
            config->ip = argv[++i];
        else if (strcmp(argv[i], "--file") == 0 && i+1 < argc)
            config->ip_file = argv[++i];
        else if (strcmp(argv[i], "--ports") == 0 && i+1 < argc)
            config->port_count = parse_ports(argv[++i], config->ports);
        else if (strcmp(argv[i], "--scan") == 0 && i+1 < argc)
            config->scan_count = parse_scan_types(argv[++i], config->scan_types);
        else if (strcmp(argv[i], "--speedup") == 0 && i+1 < argc)
            config->speedup = atoi(argv[++i]);
        else {
            fprintf(stderr, "Bilinmeyen veya eksik argüman: %s\n", argv[i]);
            exit(1);
        }
    }

    if (config->scan_count == 0) {
        config->scan_types[0] = SCAN_SYN;
        config->scan_types[1] = SCAN_NULL;
        config->scan_types[2] = SCAN_FIN;
        config->scan_types[3] = SCAN_XMAS;
        config->scan_types[4] = SCAN_ACK;
        config->scan_types[5] = SCAN_UDP;
        config->scan_count = 6;
    }

    if (config->port_count == 0) {
        for (int i = 1; i <= 1024; i++)
            config->ports[config->port_count++] = i;
    }
    
    if (!config->ip && !config->ip_file) {
        fprintf(stderr, "Hata: --ip veya --file belirtilmeli!\n");
        exit(EXIT_FAILURE);
    }

    if (config->show_help)
        print_help();
}
