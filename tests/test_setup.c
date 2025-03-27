#include "test.h"
#include <stdio.h>

int main() {
    printf("🧪 Running test_case_basic...\n");
    test_case_basic();

    printf("🧪 Running test_case_defaults...\n");
    test_case_defaults();

    printf("🧪 Running test_case_custom...\n");
    test_add_scan_result();

    printf("✅ All tests completed!\n");
    return 0;
}
