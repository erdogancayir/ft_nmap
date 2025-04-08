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

    t_shared_results *shared_results = init_shared_results(&config, queue.tail);

    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);  // ⏱ start time

    pthread_t sniffer_tid;
    pthread_create(&sniffer_tid, NULL, sniffer_thread, (void *)shared_results);

    start_thread_pool(&queue, config.speedup);

    pthread_join(sniffer_tid, NULL);

    // Add "Filtered" status for jobs with no reply
    finalize_unanswered_jobs(&queue, shared_results);

    clock_gettime(CLOCK_MONOTONIC, &end_time); // ⏱ Finish time
    double duration = (end_time.tv_sec - start_time.tv_sec)
                    + (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

    print_results(shared_results, duration);
	free_job_queue(&queue);
    free_config(&config);
	free_scan_result(shared_results->head);
	free(shared_results);
    return 0;
}
