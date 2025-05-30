#ifndef SCAN_TYPE_H
#define SCAN_TYPE_H

typedef enum 
{
    SCAN_SYN,
    SCAN_NULL,
    SCAN_FIN,
    SCAN_XMAS,
    SCAN_ACK,
    SCAN_UDP
} scan_type;

const char *scan_type_to_str(int type);

#endif