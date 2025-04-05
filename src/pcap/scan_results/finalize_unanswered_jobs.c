#include "ft_nmap.h"
#include "scan_result.h"

const char *status_for_no_response(int scan_type) {
    switch (scan_type) {
        case SCAN_SYN:
        case SCAN_ACK:
            return "Filtered";

        case SCAN_NULL:
        case SCAN_FIN:
        case SCAN_XMAS:
        case SCAN_UDP:
            return "Open|Filtered";

        default:
            return "Unknown";
    }
}

void finalize_unanswered_jobs(t_job_queue *queue, t_shared_results *results) {
    for (int i = 0; i < queue->tail; i++) {
        t_scan_job *job = &queue->jobs[i];
        bool found = false;

        pthread_mutex_lock(&results->mutex);
        t_scan_result *cur = results->head;
        while (cur) {
            if (cur->port == job->target_port &&
                cur->scan_type == job->type &&
                strcmp(cur->ip, job->target_ip) == 0) {
                found = true;
                break;
            }
            cur = cur->next;
        }
        pthread_mutex_unlock(&results->mutex);

        if (!found) {
            const char *status = status_for_no_response(job->type);
            add_scan_result(results, job->target_ip, job->target_port, job->type, status);
        }
    }
}