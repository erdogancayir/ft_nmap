#ifndef JOB_QUEUE_H
#define JOB_QUEUE_H

#define MAX_QUEUE 2048

#ifndef TH_FLAGS
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#endif

#include "scan_type.h"
#include "scan_config.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

typedef struct {
    char *target_ip;
    int target_port;
    scan_type type;
    int src_port;
} t_scan_job;

typedef struct {
    char *my_ip;
    t_scan_job *jobs;
    int head;
    int tail;
    bool stealth_mode;
    bool evade_mode;

    pthread_mutex_t mutex;
    pthread_cond_t cond;

    bool done;
} t_job_queue;

void *worker_thread(void *arg);

void init_job_queue(t_job_queue *q, char *my_ip, t_scan_config config);
bool enqueue_job(t_job_queue *q, t_scan_job job);
bool dequeue_job(t_job_queue *q, t_scan_job *job);

void start_thread_pool(t_job_queue *q, int count);
void *worker_thread(void *arg);

void print_job_debug(const t_scan_job *job, int index);
void free_job_queue(t_job_queue *q);

#endif