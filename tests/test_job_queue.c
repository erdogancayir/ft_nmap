#include "test.h"
#include "job_queue.h"
#include "ft_nmap.h"
#include <assert.h>
#include <stdio.h>
#include <pthread.h>

void test_job_queue_init() {
    t_scan_config config = {0};
    config.ports[0] = 80;
    config.port_count = 1;
    config.scan_types[0] = SCAN_SYN;
    config.scan_count = 1;
    
    t_job_queue queue;
    init_job_queue(&queue, "192.168.1.1", config);
    
    assert(queue.head == 0 && "Queue head should be initialized to 0");
    assert(queue.tail > 0 && "Queue should contain jobs after initialization");
    assert(queue.jobs != NULL && "Jobs array should be allocated");
    
    printf("✅ test_job_queue_init passed\n");
}

void test_job_queue_operations() {
    t_job_queue queue = {0};
    queue.my_ip = strdup("192.168.1.1");
    queue.head = 0;
    queue.tail = 0;
    pthread_mutex_init(&queue.mutex, NULL);
    pthread_cond_init(&queue.cond, NULL);
    
    // Test adding jobs
    t_scan_job job1 = {
        .target_ip = strdup("192.168.1.2"),
        .target_port = 80,
        .type = SCAN_SYN,
        .src_port = 12345
    };
    
    t_scan_job job2 = {
        .target_ip = strdup("192.168.1.2"),
        .target_port = 443,
        .type = SCAN_ACK,
        .src_port = 12346
    };
    
    // Test enqueuing jobs
    assert(enqueue_job(&queue, job1) && "Should successfully enqueue first job");
    assert(enqueue_job(&queue, job2) && "Should successfully enqueue second job");
    
    assert(queue.tail == 2 && "Queue should have 2 jobs");
    assert(queue.jobs[0].target_port == 80 && "First job should have port 80");
    assert(queue.jobs[1].target_port == 443 && "Second job should have port 443");
    
    // Test dequeuing jobs
    t_scan_job dequeued_job;
    assert(dequeue_job(&queue, &dequeued_job) && "Should successfully dequeue first job");
    assert(dequeued_job.target_port == 80 && "First dequeued job should have port 80");
    
    assert(dequeue_job(&queue, &dequeued_job) && "Should successfully dequeue second job");
    assert(dequeued_job.target_port == 443 && "Second dequeued job should have port 443");
    
    assert(queue.head == queue.tail && "Queue should be empty after retrieving all jobs");
    
    // Cleanup
    free(queue.my_ip);
    free(job1.target_ip);
    free(job2.target_ip);
    pthread_mutex_destroy(&queue.mutex);
    pthread_cond_destroy(&queue.cond);
    
    printf("✅ test_job_queue_operations passed\n");
}

void test_job_queue() {
    printf("🧪 Running job queue tests...\n");
    test_job_queue_init();
    test_job_queue_operations();
    printf("✅ All job queue tests passed!\n");
} 