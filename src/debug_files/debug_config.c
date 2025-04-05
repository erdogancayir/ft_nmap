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
    DEBUG_PRINT("\n🔍 " CLR_CYAN "Config Ayarları:" CLR_RESET "\n");
    DEBUG_PRINT("  Interface: " CLR_YELLOW "%s\n" CLR_RESET, config->my_interface);
    DEBUG_PRINT("  IP:        " CLR_GREEN "%s\n" CLR_RESET, config->ip ? config->ip : "None");
    DEBUG_PRINT("  IP File:   " CLR_GREEN "%s\n" CLR_RESET, config->ip_file ? config->ip_file : "None");

    DEBUG_PRINT("  Ports:     ");
    for (int i = 0; i < config->port_count && i < 10; i++)
    DEBUG_PRINT(CLR_MAGENTA "%d%s" CLR_RESET, config->ports[i], (i < config->port_count - 1 ? ", " : ""));
    if (config->port_count > 10) printf("... (+%d more)\n", config->port_count - 10);
    else DEBUG_PRINT("\n");

    DEBUG_PRINT("  Scan Types:");
    for (int i = 0; i < config->scan_count; i++) {
        DEBUG_PRINT(" " CLR_BLUE "%s" CLR_RESET, scan_type_to_str(config->scan_types[i]));
    }
    DEBUG_PRINT("\n");

    DEBUG_PRINT("  Speedup:   " CLR_YELLOW "%d\n" CLR_RESET, config->speedup);
    DEBUG_PRINT("  Show Help: " CLR_YELLOW "%s\n\n" CLR_RESET, config->show_help ? "true" : "false");
}
