#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "scan_config.h"
#include "ft_nmap.h"

void test_case_basic() {
    char *argv[] = {
        "./ft_nmap",
        "--ip", "192.168.1.1",
        "--ports", "22,80,1000-1002",
        "--scan", "SYN,FIN",
        "--speedup", "10"
    };
    int argc = sizeof(argv) / sizeof(char *);

    t_scan_config config;
    parse_args(argc, argv, &config);

    // ✅ IP kontrol (tekli liste halinde gelir)
    assert(config.ip_count == 1);
    assert(config.ip_list != NULL);
    assert(strcmp(config.ip_list[0], "192.168.1.1") == 0);

    // ✅ Portlar kontrol
    assert(config.port_count == 5);
    int expected_ports[] = {22, 80, 1000, 1001, 1002};
    for (int i = 0; i < 5; i++)
        assert(config.ports[i] == expected_ports[i]);

    // ✅ Tarama tipleri kontrol
    assert(config.scan_count == 2);
    assert(config.scan_types[0] == SCAN_SYN);
    assert(config.scan_types[1] == SCAN_FIN);

    // ✅ Speedup kontrol
    assert(config.speedup == 10);

    printf("✅ test_case_basic passed\n");
}

void test_case_defaults() {
    char *argv[] = {
        "./ft_nmap",
        "--ip", "10.0.0.1"
    };
    int argc = sizeof(argv) / sizeof(char *);

    t_scan_config config;
    parse_args(argc, argv, &config);

    // ✅ Varsayılan tarama tipleri atanmış mı?
    assert(config.scan_count == 6);
    assert(config.scan_types[0] == SCAN_SYN);
    assert(config.scan_types[5] == SCAN_UDP);

    // ✅ Varsayılan port sayısı 1024 mü?
    assert(config.port_count == 1024);
    assert(config.ports[0] == 1);
    assert(config.ports[1023] == 1024);

    printf("✅ test_case_defaults passed\n");
}