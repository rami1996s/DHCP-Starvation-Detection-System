# Detection and Mitigation of DHCP Starvation Attacks Using Entropy-Based Analysis
implemented in 2025

This project implements a lightweight, entropy-based system for **detecting and mitigating DHCP starvation attacks**. It analyzes DHCP Discover packets in `.pcap` traces, calculates entropy of MAC addresses and inter-arrival times, and flags anomalies for active defense. This approach is designed to be scalable, fast, and deployable in real-world networks.

---

##  Motivation

- **DHCP starvation attacks** flood the server with spoofed DHCP Discover packets.
- These attacks exhaust the IP pool, denying service to legitimate clients.
- Existing defenses (e.g., DHCP Snooping, rate limiting) are effective but hardware-dependent or static.
- This project proposes an **adaptive software-based detection method using Shannon entropy.**

---

##  What Is Entropy-Based Detection?

- **Shannon entropy** quantifies unpredictability in data.
- Attack traffic often shows **low entropy** (repetitive MACs or uniform timing).
- Normal traffic has **high entropy** (diverse MACs, natural timing).

This system uses:
- `H_MAC`: Entropy of MAC addresses
- `H_IAT`: Entropy of inter-arrival times
- `H_total = (H_MAC + H_IAT) / 2`

If `H_total < θ` → **Anomaly Detected**

---

##  Project Components

| Layer            | Description                                                  |
|------------------|--------------------------------------------------------------|
| Data Collection  | DHCP packets captured using `tcpdump` (.pcap files)          |
| Detection Logic  | Python script using **Scapy** to analyze and score packets   |
| Entropy Analysis | Binned IATs and MAC entropy calculated in fixed windows      |
| Mitigation       | Rate-limiting DHCP leases (e.g., 5/sec) after detection       |
| Evaluation       | Accuracy, Precision, Recall, F1-score, Detection Delay        |

---

##  How It Works

1. **Input**: `.pcap` file containing DHCP Discover packets.
2. **Windowing**: Packets are processed in chunks (e.g., 20 packets per window).
3. **Binning**: Inter-arrival times binned at 1ms resolution for entropy stability.
4. **Entropy Calculation**:
   - `H_MAC`: Diversity in MAC addresses
   - `H_IAT`: Distribution of timing
5. **Anomaly Detection**: If `H_total < θ` (default θ = 0.6), system flags attack.
6. **Mitigation**: Leases are limited (e.g., to 5/sec) during attack windows.

---

##  Performance Metrics

- **True Positives (TP)**: Attack windows correctly flagged
- **False Negatives (FN)**: Missed attacks
- **Accuracy**: TP / Total
- **Precision**: TP / (TP + False Positives)
- **Recall**: TP / (TP + FN)
- **F1-Score**: Harmonic mean of Precision and Recall
- **Detection Delay**: Time from first attack packet to detection

---

##  Scenarios Tested

###  Small Attack (100 packets)

- Detection Time: ~0.0003 sec
- Accuracy: 100%
- F1-Score: 100%
- All 5 attack windows detected immediately

###  Medium & Large Attacks

- Detected all anomalies
- Mitigation triggered after first window
- Robust to burst attacks

###  Benign Traffic

- No false positives across all tests
- Entropy stays above threshold

---

##  Parameters Evaluated

| Parameter       | Description                                   |
|----------------|-----------------------------------------------|
| `θ` (Threshold) | Range tested: 0.4–0.7 → Optimal at **0.6**     |
| `W` (Window)    | Sizes: 10, 20, 40 → Best performance at **20** |
| `bin_size`      | Best result with **0.001 sec**                |

---

