#include "job_queue.h"
#include "tcp.h"
#include "udp.h"
#include <netinet/tcp.h> // For TH_SYN, TH_FIN, TH_ACK, etc.
#include "ft_nmap.h"

void *worker_thread(void *arg) {
    t_job_queue *q = (t_job_queue *)arg;
    t_scan_job job;

    char *my_ip = q->my_ip;
    if (!my_ip || strlen(my_ip) == 0) {
        fprintf(stderr, "Error: source IP is not defined!\n");
        pthread_exit(NULL);
    }

    while (dequeue_job(q, &job)) {
        switch (job.type) {
            case SCAN_SYN:
                send_tcp_packet(my_ip, job.target_ip, job.src_port, job.target_port, TH_SYN);
                break;
            case SCAN_NULL:
                send_tcp_packet(my_ip, job.target_ip, job.src_port, job.target_port, 0x00);
                break;
            case SCAN_FIN:
                send_tcp_packet(my_ip, job.target_ip, job.src_port, job.target_port, TH_FIN);
                break;
            case SCAN_XMAS:
                send_tcp_packet(my_ip, job.target_ip, job.src_port, job.target_port, TH_FIN | TH_PUSH | TH_URG);
                break;
            case SCAN_ACK:
                send_tcp_packet(my_ip, job.target_ip, job.src_port, job.target_port, TH_ACK);
                break;
            case SCAN_UDP:
                send_udp_packet(my_ip, job.target_ip, job.src_port, job.target_port);
                break;
        }

        printf("📤 Sent to %-15s Port: %-5d Type: %s\n",
            job.target_ip,
            job.target_port,
            scan_type_to_str(job.type));

        usleep(1000);
    }

    // Mark queue as done when this worker thread finishes
    pthread_mutex_lock(&q->mutex);
    if (q->head == q->tail) {
        q->done = true;
    }
    pthread_mutex_unlock(&q->mutex);

    return NULL;
}
