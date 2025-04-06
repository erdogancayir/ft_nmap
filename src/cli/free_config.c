#include "scan_config.h"

void free_config(t_scan_config *config) {
    if (config->ip_list) {
        for (int i = 0; i < config->ip_count; i++) {
            free(config->ip_list[i]);
        }
        free(config->ip_list);
    }

    if (config->my_ip) {
        free(config->my_ip);
    }

    if (config->my_interface) {
        free(config->my_interface);
    }
}
