#include "job_queue.h"
#include "ft_nmap.h"

/**
 * Starts a pool of worker threads to process scan jobs from the queue.
 *
 * After all worker threads are created, the queue is marked as "done"
 * and a condition broadcast is sent to wake up any threads waiting for jobs.
 * Finally, the function waits for all threads to finish and cleans up.
 *
 * @param q       Pointer to the job queue shared by all threads
 * @param count   Number of worker threads to create
 */
void start_thread_pool(t_job_queue *q, int count) {
    // Allocate memory for thread handles
    pthread_t *threads = malloc(sizeof(pthread_t) * count);
    if (!threads) {
        perror("malloc failed for threads");
        exit(EXIT_FAILURE);
    }

    // Create all worker threads, passing the job queue as argument
    for (int i = 0; i < count; i++) {
        pthread_create(&threads[i], NULL, worker_thread, (void *)q);
    }

    // After job production is finished, mark the queue as done
    pthread_mutex_lock(&q->mutex);
    q->done = true;

    // Wake up all threads waiting on condition variable (e.g., empty queue waiters)
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->mutex);

    // Wait for all worker threads to finish their jobs
    for (int i = 0; i < count; i++) {
        pthread_join(threads[i], NULL);
    }

    // Clean up thread array
    free(threads);
}