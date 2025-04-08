#include "scan_result.h"

void free_scan_result(t_scan_result *result) {
	if (!result) {
		return;	
	}

	t_scan_result *cur = result;
	while (cur) {
		t_scan_result *temp = cur->next;
		free(cur->ip);
		free(cur->status);
        free(cur->hostname);
        free(cur->version);
        free(cur->os_guess);
		free(cur);
		cur = temp;
	}
}

t_shared_results *init_shared_results(t_scan_config *config, int queue_size)
{
	t_shared_results *shared_results = malloc(sizeof(t_shared_results) * config->ip_count);
    if (!shared_results) {
        free_config(config);
        perror("malloc failed for shared_results");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < config->ip_count; i++) {
        t_shared_results *result = &shared_results[i];

        result->head = NULL;
        result->interface = config->my_interface;
        result->target_ip = config->ip_list[i];
        result->my_ip = config->my_ip;
        result->response_count = 0;
        result->scan_type_count = config->scan_count;
        result->job_count = queue_size;
        pthread_mutex_init(&result->mutex, NULL);
    }
    shared_results->ip_count = config->ip_count;
	return shared_results;
}
