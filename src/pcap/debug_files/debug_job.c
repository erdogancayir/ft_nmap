#include "job_queue.h"
#include "ft_nmap.h"

// ANSI color codes
#define CLR_RESET     "\x1b[0m"
#define CLR_BOLD      "\x1b[1m"
#define CLR_BLUE      "\x1b[34m"
#define CLR_GREEN     "\x1b[32m"
#define CLR_YELLOW    "\x1b[33m"
#define CLR_CYAN      "\x1b[36m"
#define CLR_RED     "\x1b[31m"

void print_job_debug(const t_scan_job *job, int index) {
    DEBUG_PRINT(CLR_BLUE "[JOB %02d] " CLR_RESET
                "Target IP: " CLR_GREEN "%s" CLR_RESET
                ", Target Port: " CLR_YELLOW "%d" CLR_RESET
                ", Src Port: " CLR_YELLOW "%d" CLR_RESET
                ", Type: " CLR_GREEN "%s\n" CLR_RESET,
                index, job->target_ip, job->target_port, job->src_port, scan_type_to_str(job->type));
}
