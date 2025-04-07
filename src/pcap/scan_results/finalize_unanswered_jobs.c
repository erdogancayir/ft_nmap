#include "ft_nmap.h"
#include "scan_result.h"

/**
 * Returns a default status string for a scan job that received no response.
 * This mimics Nmap behavior:
 * - SYN and ACK scans: No response → "Filtered" (likely dropped by firewall)
 * - NULL, FIN, XMAS, UDP: No response → "Open|Filtered" (ambiguous due to lack of reply)
 */
const char *status_for_no_response(int scan_type) {
    switch (scan_type) {
        // If no response to SYN or ACK scan → assume packet was filtered (blocked)
        case SCAN_SYN:
        case SCAN_ACK:
            return "Filtered";

        // For these scans, no response could mean port is open OR filtered
        // because these stealth scan types expect silence from open ports
        case SCAN_NULL:
        case SCAN_FIN:
        case SCAN_XMAS:
        case SCAN_UDP:
            return "Open|Filtered";

        // Should never happen — fallback for safety
        default:
            return "Unknown";
    }
}

/**
 * Finalize unanswered scan jobs by marking them as "Filtered" or "Open|Filtered".
 * 
 * This function goes through all queued scan jobs and checks whether a result
 * was recorded for each. If a job received no response (i.e., it's not found in
 * the shared results list), it assigns a default status based on the scan type.
 *
 * This mimics Nmap's behavior: ports that don't respond are assumed to be filtered
 * (or possibly open in stealth scan types).
 */
void finalize_unanswered_jobs(t_job_queue *queue, t_shared_results *results) {
    for (int i = 0; i < queue->tail; i++) {
        t_scan_job *job = &queue->jobs[i];
        bool found = false;

        // Lock the result list to safely search for a matching result
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

        // If this job has no recorded result, add a fallback result
        if (!found) {
            const char *status = status_for_no_response(job->type);
            add_scan_result(results, job->target_ip, job->target_port, job->type, "Unknown", status);
        }
    }
}