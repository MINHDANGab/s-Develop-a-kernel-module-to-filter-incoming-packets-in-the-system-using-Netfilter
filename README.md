# Kernel Module to Filter Incoming Packets Using Netfilter

This project is a Linux kernel module that filters incoming packets using the Netfilter framework.  
It is designed to **block traffic** and **rate-limit incoming packets** from specific IP addresses before they reach the system.

> Status: **Ongoing** – basic filtering and rate limiting work, a CLI tool for rule management is planned.

---

## Features

- Inspect incoming packets at the kernel level using Netfilter hooks
- Block packets from a specific source IP address
- Apply simple rate limiting to incoming traffic from that IP
- Log events to the kernel log (`dmesg`) for debugging and verification
- Designed as a learning project for Linux kernel and Netfilter programming

---

## Architecture Overview

- The module registers a Netfilter hook for incoming packets.
- Each packet is inspected:
  - If it matches the target IP or rule, it can be **dropped**.
  - A basic **rate limit** can be enforced based on packet frequency.
- Rules are currently defined inside the module source code.
- A separate **CLI tool** is planned to:
  - Add or remove rules dynamically
  - Configure block IP and rate limits without recompiling

---

## Requirements

- Linux system with kernel module support
- Kernel headers installed (for example on Ubuntu):

