#include "job_queue.h"
#include "ft_nmap.h"

void start_thread_pool(t_job_queue *q, int count) {
    pthread_t *threads = malloc(sizeof(pthread_t) * count);
    if (!threads) {
        perror("malloc failed for threads");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < count; i++) {
        pthread_create(&threads[i], NULL, worker_thread, (void *)q);
    }

    pthread_mutex_lock(&q->mutex);
    q->done = true;
    pthread_cond_broadcast(&q->cond); // Tüm bekleyen thread'leri uyandır
    pthread_mutex_unlock(&q->mutex);

    for (int i = 0; i < count; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
}