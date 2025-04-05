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

    // Shared results for pcap thread
    t_shared_results shared_results = {
        .head = NULL, 
        .interface = config.my_interface, 
        .target_ip = config.ip, 
        .my_ip = config.my_ip,
        .job_count = queue.tail,
        .response_count = 0,
        .scan_type_count = config.scan_count,
    };

    pthread_mutex_init(&shared_results.mutex, NULL);

    pthread_t sniffer_tid;
    pthread_create(&sniffer_tid, NULL, sniffer_thread, (void *)&shared_results);

    start_thread_pool(&queue, config.speedup);

    pthread_join(sniffer_tid, NULL);

    // Add "Filtered" status for jobs with no reply
    finalize_unanswered_jobs(&queue, &shared_results);

    print_results(&shared_results);

    return 0;
}
