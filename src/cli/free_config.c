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

    if (config->spoof_ip) {
        free(config->spoof_ip);
    }

    for (int idx = 0; idx < config->decoy_count; idx++)
    {
        free(config->decoy_ips[idx]);
    }

    if (config->decoy_ips) {
        free(config->decoy_ips);
    }
}
