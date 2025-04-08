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
        uint8_t scan_flags = 0;

        switch (job.type) {
            case SCAN_SYN:
                scan_flags = TH_SYN;
                // Send TCP packet with SYN flag for SYN scan
                send_tcp_packet(q->my_ip, job.target_ip, job.src_port, job.target_port, TH_SYN, q->evade_mode);
                break;
            case SCAN_NULL:
                scan_flags = 0x00;
                // Send TCP packet with no flags for NULL scan
                send_tcp_packet(q->my_ip, job.target_ip, job.src_port, job.target_port, 0x00, q->evade_mode);
                break;
            case SCAN_FIN:
                scan_flags = TH_FIN;
                // Send TCP packet with FIN flag for FIN scan
                send_tcp_packet(q->my_ip, job.target_ip, job.src_port, job.target_port, TH_FIN, q->evade_mode);
                break;
            case SCAN_XMAS:
                scan_flags = TH_FIN | TH_PUSH | TH_URG;
                // Send TCP packet with FIN, PUSH, URG flags for XMAS scan
                send_tcp_packet(q->my_ip, job.target_ip, job.src_port, job.target_port, TH_FIN | TH_PUSH | TH_URG, q->evade_mode);
                break;
            case SCAN_ACK:
                scan_flags = TH_ACK;
                // Send TCP packet with ACK flag for ACK scan
                send_tcp_packet(q->my_ip, job.target_ip, job.src_port, job.target_port, TH_ACK, q->evade_mode);
                break;
            case SCAN_UDP:
                // Send raw UDP packet for UDP scan
                send_udp_packet(q->my_ip, job.target_ip, job.src_port, job.target_port);
                break;
        }

        // Check if decoy mode is enabled
        if (scan_flags != 0) {
            for (int i = 0; i < q->decoy_count; i++) {
                send_tcp_packet(q->decoy_ips[i], job.target_ip, job.src_port, job.target_port, scan_flags, q->evade_mode);
                print_sent_message(q->decoy_ips[i], job.target_port, scan_type_to_str(job.type));
            }
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
