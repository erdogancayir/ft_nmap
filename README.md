https://medium.com/@erdogancayir/pcap-nedir-a%C4%9F-paketlerini-yakalaman%C4%B1n-sihirli-anahtar%C4%B1-7ce4239340f6


# 🔎 ft_nmap

`ft_nmap` is a lightweight re-implementation of a portion of the original [nmap](https://nmap.org/) network scanner, developed in C. The goal of this project is to explore advanced socket programming, raw packet crafting, multithreading, and real-time packet capture using `libpcap`.

---

## 📋 Table of Contents

- [About](#about)
- [Features](#features)
- [Job Queue System](#-job-queue-system)
  - [Overview](#overview)
  - [Why a Job Queue?](#why-a-job-queue)
  - [How It Works](#how-it-works)
  - [Thread Safety](#thread-safety)
  - [Benefits](#benefits)
  - [Example Snippets](#example-snippets)
- [Build & Run](#build--run)
- [Dependencies](#dependencies)
- [License](#license)

---

## 📖 About

This project is a simplified network port scanner built using:

- Raw TCP & UDP socket programming
- Threaded job queue system
- Real-time packet listening using [`libpcap`](https://www.tcpdump.org/)
- Custom implementation of `SYN`, `ACK`, `NULL`, `FIN`, `XMAS`, and `UDP` scan techniques

> ⚠️ This project is for educational purposes only. Do not use on systems you do not own or have explicit permission to scan.

---

## 🚀 Features

- ✅ Command-line argument parser
- ✅ Multi-threaded port scanning (`--speedup`)
- ✅ Support for scanning ranges (`--ports 20-80`)
- ✅ Custom scan types: `--scan SYN,ACK,NULL,FIN,XMAS,UDP`
- ✅ Live packet capture with `libpcap`
- ✅ Clear and categorized scan result output
- ✅ Dynamic job queue with producer-consumer logic

---

## 🧵 Job Queue System

### 🔗 [Overview](#overview)

The **job queue** (`t_job_queue`) is a central mechanism in `ft_nmap` that manages the distribution of scanning tasks across multiple threads. It is designed to be **thread-safe and efficient**, ensuring maximum concurrency while maintaining correctness.

---

### 🔗 [Why a Job Queue?](#why-a-job-queue)

In a multi-threaded port scanner, it's essential to manage tasks (port scans) efficiently across worker threads. Without a job queue, threads might:

- Compete for shared resources,
- Miss tasks (or duplicate them),
- Suffer from performance issues due to contention.

The job queue enables **producer-consumer synchronization** and ensures that:

- Each job is executed exactly once,
- No two threads scan the same port/type combination,
- The main thread prepares jobs,
- Worker threads focus purely on sending packets.

---

### 🔗 [How It Works](#how-it-works)

### 🧪 Scan Job Generation

A **scan job** is created for each combination of **port** and **scan type**. This allows fine-grained control over how each port is probed using different techniques (e.g., SYN, UDP, etc.).

---

#### 📋 Example

If the user provides:
- Ports: `22`, `80`
- Scan Types: `SYN`, `UDP`

Then the following jobs will be generated and added to the job queue:

| Target IP | Port | Scan Type |
|-----------|------|-----------|
| x.x.x.x   | 22   | SYN       |
| x.x.x.x   | 22   | UDP       |
| x.x.x.x   | 80   | SYN       |
| x.x.x.x   | 80   | UDP       |

This matrix-like expansion ensures that **every specified port is scanned with every specified scan type**.

---
