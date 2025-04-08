#include "scan_result.h"
#include <pthread.h>
#include "ft_nmap.h"
#include "job_queue.h"

void add_scan_result(t_shared_results *results, const char *ip, int port, scan_type scan_type, const char *os_guess, const char *status) {
    t_scan_result *new_result = malloc(sizeof(t_scan_result));
    new_result->ip = strdup(ip);
    new_result->port = port;
    new_result->scan_type = scan_type;
    new_result->status = strdup(status);
    new_result->hostname = reverse_dns_lookup(ip);
    new_result->next = NULL;
    new_result->version = NULL;
    new_result->os_guess = strdup(os_guess);

    pthread_mutex_lock(&results->mutex);

    new_result->next = results->head;
    results->head = new_result;

    pthread_mutex_unlock(&results->mutex);

    print_scan_result_log(ip, port, scan_type, status);
}
