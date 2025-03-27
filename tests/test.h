#ifndef TEST_H
#define TEST_H
#include "scan_result.h"

void test_case_basic();
void test_case_defaults();
void add_scan_result(t_shared_results *results, const char *ip, int port, int scan_type, const char *status);
void test_add_scan_result();

#endif