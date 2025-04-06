#include "ft_nmap.h"
#include "scan_config.h"

// ANSI color codes
#define CLR_RED     "\x1b[31m"
#define CLR_GREEN   "\x1b[32m"
#define CLR_YELLOW  "\x1b[33m"
#define CLR_BLUE    "\x1b[34m"
#define CLR_MAGENTA "\x1b[35m"
#define CLR_CYAN    "\x1b[36m"
#define CLR_RESET   "\x1b[0m"

void print_config(t_scan_config *config) {
    printf("\n🔍 " CLR_CYAN "Scan Configurations:" CLR_RESET "\n");
    printf("  Interface: " CLR_YELLOW "%s\n" CLR_RESET, config->my_interface);
    
    if (config->ip_list && config->ip_count) {
        printf("  IP  Targets:   ");
        for (int i = 0; i < config->ip_count && i < 5; i++) {
            printf(CLR_GREEN "%s%s" CLR_RESET, config->ip_list[i], (i < config->ip_count - 1 ? ", " : ""));
        }
        if (config->ip_count > 5)
            printf("... (+%d more)\n", config->ip_count - 5);
        else
            printf("\n");
    } else {
        printf("  IP:        " CLR_RED "None\n" CLR_RESET);
    }

    printf("  Ports:     ");
    for (int i = 0; i < config->port_count && i < 10; i++)
        printf(CLR_MAGENTA "%d%s" CLR_RESET, config->ports[i], (i < config->port_count - 1 ? ", " : ""));
    if (config->port_count > 10) printf("... (+%d more)\n", config->port_count - 10);
    else printf("\n");

    printf("  Scan Types:");
    for (int i = 0; i < config->scan_count; i++) {
        printf(" " CLR_BLUE "%s" CLR_RESET, scan_type_to_str(config->scan_types[i]));
    }
    printf("\n");

    printf("  Speedup:   " CLR_YELLOW "%d\n" CLR_RESET, config->speedup);
}