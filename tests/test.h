#ifndef TEST_H
#define TEST_H
#include "scan_result.h"
#include "job_queue.h"
#include "scan_type.h"

void test_case_basic();
void test_case_defaults();
void add_scan_result(t_shared_results *results, const char *ip, int port, scan_type scan_type, const char *status);
void test_add_scan_result();

// Job queue test functions
void test_job_queue();
void test_job_queue_init();
void test_job_queue_operations();
void test_job_queue_edge_cases();
void test_job_queue_concurrent();

#endif