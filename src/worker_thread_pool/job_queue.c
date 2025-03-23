#include "job_queue.h"
#include "scan_config.h"

void init_job_queue(t_job_queue *q, char *my_ip, t_scan_config config) {
    q->head = q->tail = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond, NULL);
    q->my_ip = my_ip;

     // Job enqueue
    for (int i = 0; i < config.port_count; i++) {
        for (int j = 0; j < config.scan_count; j++) {
            t_scan_job job;
            job.target_ip = config.ip;
            job.target_port = config.ports[i];
            job.src_port = 40000 + i; // farklı source portlar
            job.type = config.scan_types[j];
            enqueue_job(q, job);
        }
    }
}

bool enqueue_job(t_job_queue *q, t_scan_job job) {
    pthread_mutex_lock(&q->mutex);
    int next = (q->tail + 1) % MAX_QUEUE;
    if (next == q->head) {
        pthread_mutex_unlock(&q->mutex);
        return false; // full
    }
    q->jobs[q->tail] = job;
    q->tail = next;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mutex);
    return true;
}

bool dequeue_job(t_job_queue *q, t_scan_job *job) {
    pthread_mutex_lock(&q->mutex);
    while (q->head == q->tail) {
        pthread_cond_wait(&q->cond, &q->mutex);
    }
    *job = q->jobs[q->head];
    q->head = (q->head + 1) % MAX_QUEUE;
    pthread_mutex_unlock(&q->mutex);
    return true;
}