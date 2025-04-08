#include "job_queue.h"
#include "tcp.h"
#include "udp.h"
#include <netinet/tcp.h>
#include "ft_nmap.h"

/**
 * Worker thread function that continuously pulls scan jobs from the queue
 * and sends the appropriate probe (TCP or UDP) to the target.
 *
 * Each worker:
 * - Dequeues a job
 * - Sends the scan packet based on the scan type
 * - Logs the action
 *
 * If the queue is empty and marked as done, the thread exits gracefully.
 *
 * @param arg Pointer to the shared job queue (cast from void*)
 * @return NULL (thread exit)
 */
void *worker_thread(void *arg) {
    t_job_queue *q = (t_job_queue *)arg;
    t_scan_job job;

    // Ensure source IP is set before sending packets
    if (!q->my_ip || strlen(q->my_ip) == 0) {
        fprintf(stderr, "Error: source IP is not defined!\n");
        pthread_exit(NULL);
    }

    // Continuously fetch and execute jobs from the queue
    while (dequeue_job(q, &job)) {
        switch (job.type) {
            case SCAN_SYN:
                // Send TCP packet with SYN flag for SYN scan
                send_tcp_packet(q->my_ip, job.target_ip, job.src_port, job.target_port, TH_SYN);
                break;
            case SCAN_NULL:
                // Send TCP packet with no flags for NULL scan
                send_tcp_packet(q->my_ip, job.target_ip, job.src_port, job.target_port, 0x00);
                break;
            case SCAN_FIN:
                // Send TCP packet with FIN flag for FIN scan
                send_tcp_packet(q->my_ip, job.target_ip, job.src_port, job.target_port, TH_FIN);
                break;
            case SCAN_XMAS:
                // Send TCP packet with FIN, PUSH, URG flags for XMAS scan
                send_tcp_packet(q->my_ip, job.target_ip, job.src_port, job.target_port, TH_FIN | TH_PUSH | TH_URG);
                break;
            case SCAN_ACK:
                // Send TCP packet with ACK flag for ACK scan
                send_tcp_packet(q->my_ip, job.target_ip, job.src_port, job.target_port, TH_ACK);
                break;
            case SCAN_UDP:
                // Send raw UDP packet for UDP scan
                send_udp_packet(q->my_ip, job.target_ip, job.src_port, job.target_port);
                break;
        }

        // Print formatted output for each sent scan attempt
        print_sent_message(job.target_ip, job.target_port, scan_type_to_str(job.type));

        // 🧩 Timing-Based Evasion: Stealth Mode (100ms delay)
        if (q->stealth_mode) {
            usleep(100000);  // 100 milliseconds
        } else {
            usleep(1000);  // default: 1 millisecond
        }
    }

    return NULL;
}
