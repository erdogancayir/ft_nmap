#include "scan_config.h"
#include "ft_nmap.h"
#include "job_queue.h"
#include "scan_result.h"

int main(int argc, char **argv) {
    t_scan_config config;
    parse_args(argc, argv, &config);

    // Job queue init
    t_job_queue queue;
    init_job_queue(&queue, config.ip, config);

    if (config.speedup <= 0) config.speedup = 1;
    if (config.speedup > 250) config.speedup = 250;

    // Shared results for pcap thread
    t_shared_results shared_results = { .head = NULL };
    pthread_mutex_init(&shared_results.mutex, NULL);


    //pthread_t pcap_thread;
    //pthread_create(&pcap_thread, NULL, pcap_listener_thread, &shared_results);

    start_thread_pool(&queue, config.speedup);

    //pthread_join(pcap_thread, NULL);

    //pthread_mutex_destroy(&shared_results.mutex);

    return 0;
}
