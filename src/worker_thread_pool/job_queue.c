#include "job_queue.h"
#include "scan_config.h"
#include "ft_nmap.h"

/**
 * Initializes the job queue and fills it with scanning tasks.
 * 
 * Each job corresponds to one scan type and one port (e.g., SYN scan on port 80).
 * A unique source port is generated for each job using the formula:
 *      src_port = PORT_SCAN_BASE + (i * scan_count + j)
 * 
 * @param q        Pointer to the job queue structure
 * @param my_ip    Local IP address to be used as source
 * @param config   Parsed scan configuration with ports and scan types
 */
void init_job_queue(t_job_queue *q, char *my_ip, t_scan_config config) {
    // Initialize queue state
    q->stealth_mode = config.stealth_mode;
    q->head = q->tail = 0;
    q->done = false;

    pthread_mutex_init(&q->mutex, NULL);

    pthread_cond_init(&q->cond, NULL);

    q->my_ip = my_ip;

    int job_index = 0;
	int total_jobs = config.ip_count * config.port_count * config.scan_count;
	q->jobs = malloc(sizeof(t_scan_job) * total_jobs);

    // Loop through each target IP in the list
    for (int ip_idx = 0; ip_idx < config.ip_count; ip_idx++) {
        char *target_ip = config.ip_list[ip_idx];

        // Enqueue a job for each (target_ip, port, scan_type) combination
        for (int i = 0; i < config.port_count; i++) {
            for (int j = 0; j < config.scan_count; j++) {
                t_scan_job job;
                job.target_ip = target_ip;
                job.target_port = config.ports[i];
                job.src_port = PORT_SCAN_BASE + (job_index);  // Unique src port per job
                job.type = config.scan_types[j];

                enqueue_job(q, job);                     // Add job to the queue
                print_job_debug(&job, job_index++);      // Debug print
            }
        }
    }
}

/**
 * Adds a scan job to the circular job queue.
 *
 * @param q     Pointer to the job queue
 * @param job   Scan job to enqueue
 * @return      true if successful, false if the queue is full
 */
bool enqueue_job(t_job_queue *q, t_scan_job job) {
    pthread_mutex_lock(&q->mutex);

    int next = (q->tail + 1) % MAX_QUEUE;
    if (next == q->head) {
        pthread_mutex_unlock(&q->mutex);
        return false; // Queue full
    }

    q->jobs[q->tail] = job;
    q->tail = next;

    pthread_cond_signal(&q->cond); // ✅ önemli
    pthread_mutex_unlock(&q->mutex);
    return true;
}

/**
 * Removes a scan job from the job queue for a worker thread to process.
 *
 * If the queue is empty, the thread waits using a condition variable.
 * If the queue is marked as "done", the thread exits gracefully.
 *
 * @param q     Pointer to the job queue
 * @param job   Output: job structure to fill
 * @return      true if a job was dequeued, false if the queue is done and empty
 */
bool dequeue_job(t_job_queue *q, t_scan_job *job) {
    pthread_mutex_lock(&q->mutex);

    while (q->head == q->tail) {
        if (q->done) {
            // No more jobs will be added — exit gracefully
            pthread_mutex_unlock(&q->mutex);
            return false;
        }
        // Wait until a new job is enqueued or the queue is marked done
        pthread_cond_wait(&q->cond, &q->mutex);
    }

    // Dequeue the job
    *job = q->jobs[q->head];
    q->head = (q->head + 1) % MAX_QUEUE;

    pthread_mutex_unlock(&q->mutex);

    return true;
}

void free_job_queue(t_job_queue *q) {
	free(q->jobs);
	pthread_mutex_destroy(&q->mutex);
	pthread_cond_destroy(&q->cond);
}