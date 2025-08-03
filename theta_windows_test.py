from collections import defaultdict
from scapy.layers.l2 import Ether
from scapy.all import rdpcap, DHCP
import math
import time

# --- Helper Functions ---
def normalized_entropy(values):
    if not values:
        return 0.0
    value_counts = {}
    for v in values:
        value_counts[v] = value_counts.get(v, 0) + 1
    total = len(values)
    entropy = -sum((count / total) * math.log2(count / total) for count in value_counts.values())
    max_entropy = math.log2(len(value_counts)) if len(value_counts) > 1 else 1
    return entropy / max_entropy if max_entropy > 0 else 0.0

def bin_iats(iats, bin_size=0.001):
    return [round(iat / bin_size) * bin_size for iat in iats]

# --- Load Packets ---
start_time = time.time()
packets = rdpcap("dhcp_starvation.pcap")  # Replace with benign trace to test normal
print(f"Total packets in capture: {len(packets)}")

# --- Extract DHCP Discover packets ---
discovers = []
for pkt in packets:
    if pkt.haslayer(DHCP) and pkt[DHCP].options[0][1] == 1:
        mac = pkt[Ether].src
        ts = pkt.time
        discovers.append((ts, mac))

print(f"Total DHCP Discover packets: {len(discovers)}")
if not discovers:
    print(" No DHCP Discover packets found.")
    exit()

attack_start_time = discovers[0][0]

# --- Parameters ---
window_sizes = [10, 20, 30]
thresholds = [0.4, 0.5, 0.6, 0.7]

print("\n Evaluation Results (with Mitigation):")
print("W\t\tTP\tFN\tAcc\tPrec\tRecall\tF1\tDetect?\tDelay(s)\tBlocked")

for W in window_sizes:
    for theta in thresholds:
        TP = FP = FN = 0
        attack_detected = False
        detection_time = None
        blocked_macs = set()

        for i in range(0, len(discovers), W):
            window = discovers[i:i+W]
            if len(window) < W:
                break

            timestamps = [t for t, _ in window]
            macs = [m for _, m in window]

            mac_entropy = normalized_entropy(macs)
            iats = [timestamps[j] - timestamps[j - 1] for j in range(1, len(timestamps))]
            binned_iats = bin_iats(iats)
            iat_entropy = normalized_entropy(binned_iats)

            alpha = 0.3
            H_total = alpha * mac_entropy + (1 - alpha) * iat_entropy

            if H_total < theta:
                TP += 1
                if not attack_detected:
                    detection_time = timestamps[-1]
                    attack_detected = True
                blocked_macs.update(macs)  # ? Mitigation action
            else:
                FN += 1

        # Attack inference
        IS_ATTACK_TRACE = any(mac != discovers[0][1] for _, mac in discovers)
        if not IS_ATTACK_TRACE:
            TP = FN = 0

        if TP + FN == 0:
            acc = prec = rec = f1 = "N/A"
        else:
            acc = TP / (TP + FN)
            prec = TP / (TP + FP) if TP + FP > 0 else 0
            rec = TP / (TP + FN)
            f1 = 2 * prec * rec / (prec + rec) if prec + rec > 0 else 0
            acc = f"{acc:.2f}"
            prec = f"{prec:.2f}"
            rec = f"{rec:.2f}"
            f1 = f"{f1:.2f}"

        delay_str = f"{(detection_time - attack_start_time):.2f}" if detection_time else "N/A"
        detect_str = "?" if attack_detected else "?"
        print(f"{W}\t{theta:.1f}\t{TP}\t{FN}\t{acc}\t{prec}\t{rec}\t{f1}\t{detect_str}\t{delay_str}\t{len(blocked_macs)}")

# --- Runtime ---
print(f"\n Evaluation completed in {time.time() - start_time:.2f} seconds.")
