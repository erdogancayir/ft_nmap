#include "job_queue.h"
#include "scan_config.h"
#include "ft_nmap.h"

void init_job_queue(t_job_queue *q, char *my_ip, t_scan_config config) {
    q->head = q->tail = 0;
    q->done = false;

    pthread_mutex_init(&q->mutex, NULL);
    q->my_ip = my_ip;

     // Job enqueue
    for (int i = 0; i < config.port_count; i++) {
        for (int j = 0; j < config.scan_count; j++) {
            t_scan_job job;
            job.target_ip = config.ip;
            job.target_port = config.ports[i];
            job.src_port = PORT_SCAN_BASE + i; // different src port for each job
            job.type = config.scan_types[j];
            enqueue_job(q, job);
        }
    }
}

bool enqueue_job(t_job_queue *q, t_scan_job job) {
    int next = (q->tail + 1) % MAX_QUEUE;
    if (next == q->head) {
        return false; // full
    }
    q->jobs[q->tail] = job;
    q->tail = next;
    return true;
}

bool dequeue_job(t_job_queue *q, t_scan_job *job) {
    pthread_mutex_lock(&q->mutex);
    
    while (q->head == q->tail) {
        if (q->done) {
            pthread_mutex_unlock(&q->mutex);
            return false;
        }
        pthread_cond_wait(&q->cond, &q->mutex); // Bekle ama done değişirse uyan
    }

    *job = q->jobs[q->head];
    q->head = (q->head + 1) % MAX_QUEUE;

    pthread_mutex_unlock(&q->mutex);

    return true;
}