#include "scan_result.h"

void print_results(t_shared_results *results) {
    t_scan_result *current = results->head;

    // 1. Open ve diğerleri için iki ayrı liste tut (veya ayırıcı yaz)
    printf("Open ports:\n");
    printf("Port Service Name Results Conclusion\n");

    while (current) {
        if (strcmp(current->status, "Open") == 0) {
            // print open port info
        }
        current = current->next;
    }

    // 2. Diğer sonuçlar
    current = results->head;
    printf("Closed/Filtered/Unfiltered ports:\n");

    while (current) {
        if (strcmp(current->status, "Open") != 0) {
            // print filtered/closed/etc.
        }
        current = current->next;
    }
}
