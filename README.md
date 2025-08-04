# DHCP Starvation Attack Detection and Mitigation Using Entropy-Based Analysis
implemeneted in 2025

This project implements a lightweight, entropy-based system to detect and mitigate **DHCP starvation attacks** using offline `.pcap` traces. The detection mechanism analyzes statistical entropy patterns in DHCP traffic to distinguish legitimate usage from automated attacks.

---

##  Table of Contents

- [Motivation](#motivation)
- [Background](#background)
- [Detection and Mitigation Approach](#detection-and-mitigation-approach)
- [GNS3 Network Topology](#gns3-network-topology)
- [Experimental Setup](#experimental-setup)
- [Evaluation](#evaluation)
- [Visualization](#visualization)
- [Conclusion](#conclusion)
- [Limitations & Future Work](#limitations--future-work)

---

##  Motivation

DHCP is a core protocol for dynamically assigning IP addresses in networks. However, it is vulnerable to **DHCP Starvation Attacks**, where an attacker floods the network with spoofed `DHCP Discover` packets to exhaust the DHCP server’s IP pool, leading to a denial of service for legitimate clients.

**Goal**: To design a fast, lightweight detection system using entropy-based analysis to identify and mitigate DHCP starvation attacks.

---

##  Background

###  DHCP Protocol: The DORA Process

1. **Discover** – Client requests an IP
2. **Offer** – Server responds with available IP
3. **Request** – Client requests the offered IP
4. **ACK** – Server confirms the lease

###  DHCP Starvation Attack

- Attacker sends a flood of spoofed `DHCP Discover` packets with fake MAC addresses
- The server assigns IPs for each spoofed MAC until the pool is exhausted
- Legitimate clients are denied service
- Common attack tool: **Yersinia**

---

##  Detection and Mitigation Approach

###  Entropy-Based Detection

- **Shannon Entropy** is used to detect randomness in:
  - **MAC Addresses** (`H_MAC`)
  - **Inter-Arrival Times** (`H_IAT`)
- Sudden drops in entropy indicate suspicious behavior
- Combines both into a unified score: `H_total = f(H_MAC, H_IAT)`
- Anomaly Trigger: `H_total < θ` (Threshold θ = 0.6)

###  Implementation

- Implemented in **Python** using the **Scapy** library
- Input: `.pcap` files captured with `tcpdump`
- Analysis is performed in **sliding windows** (W = 20 packets)
- **Bin size for IATs**: 0.001 seconds (for stable entropy estimation)
- **Detection Time** is measured relative to attack onset
- **Mitigation Strategy**:
  - Lease rate limit: R = 5 leases/second
  - If exceeded: block DHCP Discover packets for 2 seconds

---

##  GNS3 Network Topology

This project was tested on a virtual network topology simulated using **GNS3**, which included:

- **Kali Linux**: Simulated attacker (Yersinia) and benign traffic generator
- **PCs**: Legitimate DHCP clients
- **DHCP Server**
- **Traffic Monitor**: `tcpdump` for packet capture

### Features of the GNS3 Setup

- Fully virtualized testbed with isolated control
- Easy replication and modification of scenarios
- Dual-trace approach:
  - **Attack Trace**: Using Yersinia tool from Kali
  - **Benign Trace**: Generated using a custom Python script

---

##  Experimental Setup

###  Scenarios Evaluated

- **Small Attack (A1)** – 100 packets
- **Medium & Large Attacks (A2, A3)** – Scaled packet volume
- **Benign Scenarios (B1, B2, B3)** – Simulated normal clients

###  Metrics Evaluated

- **True Positives (TP)**
- **False Negatives (FN)**
- **Accuracy**
- **Precision**
- **Recall**
- **F1 Score**
- **Detection Delay**
- **Total Analysis Time**

---

##  Evaluation

###  Attack Detection

- **100% detection rate** for all attack sizes
- Detection delay as low as **0.0003 seconds**
- Zero false negatives across all tests

###  Benign Trace Classification

- All benign traces correctly classified
- **Zero false positives** for θ ≤ 0.6

###  Parameter Sensitivity

- **Window Size (W)**:
  - Smaller = faster response
  - Larger = smoother behavior
- **Entropy Threshold (θ)**:
  - θ = 0.6 → optimal tradeoff
  - θ > 0.6 → risk of false positives

---

##  Visualization

###  Benign Traffic

- DHCP Discover rate remains below R = 5
- No entropy anomalies → no mitigation triggered

###  Attack Traffic

- Massive burst in Discover packets (e.g., 40/1ms)
- Entropy sharply drops → anomaly detected
- Mitigation kicks in immediately

###  Bin Size Impact

- **Best bin size**: 0.001 seconds
  - Balances detection power and false positive control
  - Works consistently across benign and attack traces

---

##  Conclusion

-  **Lightweight**, fast, and accurate
-  Zero false positives across all benign traces
-  No reliance on deep packet inspection
-  Real-time ready (10K packets analyzed in < 7s)
-  Clear, interpretable metrics

---

##  Limitations & Future Work

-  Currently limited to **offline `.pcap`** analysis
-  Future: Support **live interface monitoring**
-  Explore **machine learning** for adaptive threshold (θ) tuning
-  Integration with **switch/firewall rule automation**

