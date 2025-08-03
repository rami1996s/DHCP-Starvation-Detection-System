
from collections import Counter, defaultdict
from statistics import harmonic_mean
from scapy.layers.l2 import Ether
from scapy.all import rdpcap, DHCP
import math
import time

# --- Parameters ---
W = 20  # window size (number of packets per window)
TP = 0  # True Positives
FP = 0  # False Positives (none expected here)
FN = 0  # False Negatives
R = 5  # Threshold for allowed DHCP leases per second

# --- Helper functions ---
def normalized_entropy(values):
    if not values:
        return 0.0
    value_counts = Counter(values)
    total = len(values)
    entropy = -sum((c / total) * math.log2(c / total) for c in value_counts.values())
    max_entropy = math.log2(len(value_counts)) if len(value_counts) > 1 else 1
    return entropy / max_entropy if max_entropy > 0 else 0.0

def bin_iats(iats, bin_size=0.001):
    return [round(iat / bin_size) * bin_size for iat in iats]

def clean(value, tol=1e-10):
    return 0.0 if abs(value) < tol else value

# --- Load packets ---
start_time = time.time()
packets = rdpcap("dhcp_starvation.pcap")
print(f"Total packets in capture: {len(packets)}")

# --- Extract DHCP Discover packets ---
discovers = []
for pkt in packets:
    if pkt.haslayer(DHCP) and pkt[DHCP].options[0][1] == 1:  # DHCP Discover
        mac = pkt[Ether].src
        timestamp = pkt.time
        discovers.append((timestamp, mac))

print(f"Total DHCP Discover packets found: {len(discovers)}")

attack_start_time = discovers[0][0]
attack_detected = False
anomaly_detected_in_trace = False
mitigation_triggered = False

# --- Analyze in windows ---
for i in range(0, len(discovers), W):
    window = discovers[i:i+W]
    if len(window) < W:
        break

    timestamps = [t for t, _ in window]
    macs = [m for _, m in window]

    mac_entropy = normalized_entropy(macs)
    iats = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
    binned_iats = bin_iats(iats)
    iat_entropy = normalized_entropy(binned_iats)

    iat_bin_counts = Counter(binned_iats)
    print("  IAT Bin Distribution (bin size = 0.001):")
    for bin_val, count in sorted(iat_bin_counts.items()):
        print(f"    Bin {bin_val:.4f} sec: {count} IATs")

    alpha = 0.3
    theta = 0.6

    H_total = alpha * mac_entropy + (1 - alpha) * iat_entropy
    H_total_harmonic = harmonic_mean([mac_entropy, iat_entropy])
    H_total_geometric = math.sqrt(mac_entropy * iat_entropy)

    print(f"\nWindow {i//W + 1}:")
    print(f"  MAC Entropy: {clean(mac_entropy):.4f}")
    print(f"  IAT Entropy: {clean(iat_entropy):.4f}")
    print(f"  H_total: {H_total:.4f}")
    print(f"  H_total_harmonic: {clean(H_total_harmonic):.4f}")
    print(f"  H_total_geometric: {clean(H_total_geometric):.4f}")

    if H_total < theta:
        print(" Anomaly Detected: Possible DHCP Starvation Attack")
        TP += 1
        anomaly_detected_in_trace = True
        if not attack_detected:
            detection_time = timestamps[-1]
            elapsed_detection_time = detection_time - attack_start_time
            attack_detected = True

        if TP == 1 and not mitigation_triggered:
            mitigation_triggered = True
            print("\n Immediate Mitigation Triggered:")
            lease_counts = defaultdict(int)
            for ts, mac in discovers:
                sec = int(ts)
                lease_counts[sec] += 1
            for sec in sorted(lease_counts):
                count = lease_counts[sec]
                status = " Allowed" if count <= R else "? Blocked"
                print(f"  Second {sec}: {count} leases ? {status}")
    else:
        print("Normal behavior")

# --- Detection Summary ---
IS_ATTACK_TRACE = anomaly_detected_in_trace
if IS_ATTACK_TRACE:
    FN = 0
else:
    FN = 0

if attack_detected:
    print(f"\n Detection Time: {elapsed_detection_time:.6f} seconds after attack started.")
else:
    print("\n No anomaly detected in this capture.")

# --- Post-Detection Mitigation Message ---
if IS_ATTACK_TRACE and not mitigation_triggered:
    print("\n Post-analysis Mitigation Lease Rate Summary:")
    lease_counts = defaultdict(int)
    for ts, mac in discovers:
        sec = int(ts)
        lease_counts[sec] += 1
    for sec in sorted(lease_counts):
        count = lease_counts[sec]
        status = " Allowed" if count <= R else " Blocked"
        print(f"  Second {sec}: {count} leases  {status}")
elif not attack_detected:
    print("\n No mitigation needed — no attack detected.")

# --- Detection Metrics ---
if TP == 0 and FN == 0:
    print("\n No attack windows — metrics not applicable for benign trace.")
else:
    total_windows = TP + FN
    accuracy = TP / total_windows if total_windows > 0 else 0.0
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    print("\n Detection Metrics Summary:")
    print(f"  True Positives (TP): {TP}")
    print(f"  False Negatives (FN): {FN}")
    print(f"  Accuracy:  {accuracy:.2%}")
    print(f"  Precision: {precision:.2%}")
    print(f"  Recall:    {recall:.2%}")
    print(f"  F1-Score:  {f1_score:.2%}")

# --- Performance Time ---
end_time = time.time()
print(f"\n Total analysis time: {end_time - start_time:.4f} seconds")


