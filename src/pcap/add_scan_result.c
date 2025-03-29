#include "scan_result.h"
#include <pthread.h>

void add_scan_result(t_shared_results *results, const char *ip, int port, int scan_type, const char *status) {

    printf("Adding scan result: %s:%d (type: %d, status: %s)\n", ip, port, scan_type, status);

    // 1. Yeni bir result node oluştur
    t_scan_result *new_result = malloc(sizeof(t_scan_result));
    new_result->ip = strdup(ip);
    new_result->port = port;
    new_result->scan_type = scan_type;
    new_result->status = strdup(status);
    new_result->next = NULL;

    // 2. Thread-safe ekleme
    pthread_mutex_lock(&results->mutex);

    // Başa ekle
    new_result->next = results->head;
    results->head = new_result;

    pthread_mutex_unlock(&results->mutex);
}
