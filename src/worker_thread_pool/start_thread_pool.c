#include "job_queue.h"

void start_thread_pool(t_job_queue *q, int count) {
    pthread_t *threads = malloc(sizeof(pthread_t) * count);
    if (!threads) {
        perror("malloc failed for threads");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < count; i++) {
        pthread_create(&threads[i], NULL, worker_thread, (void *)q);
    }

    for (int i = 0; i < count; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_mutex_lock(&q->mutex);
    q->done = true; // ✅ iş bitti
    pthread_cond_broadcast(&q->cond); // ✅ tüm bekleyenleri uyandır
    pthread_mutex_unlock(&q->mutex);

    free(threads);
}