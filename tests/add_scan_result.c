#include "scan_config.h"
#include "scan_result.h"
#include "assert.h"
#include <pthread.h>
#include "test.h"

void test_add_scan_result() {
    t_shared_results results;
    results.head = NULL;
    pthread_mutex_init(&results.mutex, NULL);

    add_scan_result(&results, "192.168.1.1", 80, SCAN_SYN, "Open");

    assert(results.head != NULL);
    assert(strcmp(results.head->ip, "192.168.1.1") == 0);
    assert(results.head->port == 80);
    assert(results.head->scan_type == SCAN_SYN);
    assert(strcmp(results.head->status, "Open") == 0);

    pthread_mutex_destroy(&results.mutex);
}
