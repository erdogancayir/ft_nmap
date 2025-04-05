#include "scan_result.h"
#include "ft_nmap.h"

// ANSI color codes
#define CLR_RESET     "\x1b[0m"
#define CLR_BOLD      "\x1b[1m"
#define CLR_BLUE      "\x1b[34m"
#define CLR_GREEN     "\x1b[32m"
#define CLR_YELLOW    "\x1b[33m"
#define CLR_CYAN      "\x1b[36m"
#define CLR_RED     "\x1b[31m"

void print_scan_result_log(const char *ip, int port, int scan_type, const char *status) {
    const char *color;

    if (strcmp(status, "Open") == 0)
        color = CLR_GREEN;
    else if (strcmp(status, "Closed") == 0)
        color = CLR_RED;
    else if (strcmp(status, "Filtered") == 0)
        color = CLR_YELLOW;
    else
        color = CLR_BLUE;

    DEBUG_PRINT(CLR_BLUE "[SCAN RESULT]" CLR_RESET " IP: " CLR_CYAN "%s" CLR_RESET
                " Port: " CLR_CYAN "%d" CLR_RESET
                " Type: " CLR_CYAN "%s" CLR_RESET
                " Status: %s%s%s\n",
                ip, port, scan_type_to_str(scan_type), color, status, CLR_RESET);
}
