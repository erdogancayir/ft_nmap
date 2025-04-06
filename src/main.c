#include "scan_config.h"
#include "ft_nmap.h"
#include "job_queue.h"
#include "scan_result.h"
#include <pthread.h>

int main(int argc, char **argv) {

    t_scan_config config;
    parse_args(argc, argv, &config);

    // Job queue init
    t_job_queue queue;

    init_job_queue(&queue, config.my_ip, config);

    t_shared_results *shared_results = malloc(sizeof(t_shared_results) * config.ip_count);
    if (!shared_results) {
        perror("malloc failed for shared_results");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < config.ip_count; i++) {
        t_shared_results *result = &shared_results[i];

        result->head = NULL;
        result->interface = config.my_interface;
        result->target_ip = config.ip_list[i];
        result->my_ip = config.my_ip;
        result->response_count = 0;
        result->scan_type_count = config.scan_count;
        result->job_count = queue.tail;
        pthread_mutex_init(&result->mutex, NULL);
    }

    shared_results->ip_count = config.ip_count;

    pthread_t sniffer_tid;
    pthread_create(&sniffer_tid, NULL, sniffer_thread, (void *)shared_results);

    start_thread_pool(&queue, config.speedup);

    pthread_join(sniffer_tid, NULL);

    // Add "Filtered" status for jobs with no reply
    finalize_unanswered_jobs(&queue, shared_results);

    print_results(shared_results);

    return 0;
}
