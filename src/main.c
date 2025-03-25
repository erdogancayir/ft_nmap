#include "scan_config.h"
#include "ft_nmap.h"
#include "job_queue.h"

int main(int argc, char **argv) {
    t_scan_config config;
    parse_args(argc, argv, &config);

    // Job queue init
    t_job_queue queue;
    init_job_queue(&queue, config.ip, config);

    if (config.speedup <= 0) config.speedup = 1;
    if (config.speedup > 250) config.speedup = 250;
    
    start_thread_pool(&queue, config.speedup);
    

    return 0;
}
