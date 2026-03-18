"""
Real-time packet capture script for Electron UI
Captures network packets and aggregates flows
"""
import sys
import time
import csv
from scapy.all import sniff, IP, TCP, UDP

capture_flows = {}
capture_running = True
output_file = "captured.csv"

def on_packet(pkt):
    """Process each captured packet"""
    if IP not in pkt:
        return

    ip = pkt[IP]
    src = ip.src
    dst = ip.dst
    proto = int(ip.proto)
    sport = ""
    dport = ""

    if TCP in pkt:
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
    elif UDP in pkt:
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)

    key = (src, dst, proto, sport, dport)
    now = time.time()
    size = len(bytes(pkt))

    if key not in capture_flows:
        capture_flows[key] = {"bytes": size, "start": now, "end": now, "count": 1}
    else:
        capture_flows[key]["bytes"] += size
        capture_flows[key]["end"] = now
        capture_flows[key]["count"] += 1

    # Print progress every 10 packets
    total_packets = sum(f["count"] for f in capture_flows.values())
    if total_packets % 10 == 0:
        print(f"Captured {total_packets} packets, {len(capture_flows)} flows", flush=True)

def write_csv():
    """Write captured flows to CSV file"""
    try:
        with open(output_file, "w", encoding="utf-8", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Source", "Destination", "Protocol", "SrcPort", "DstPort", "DataSize", "Duration"])

            for (src, dst, proto, sport, dport), agg in capture_flows.items():
                duration = max(0.0, agg["end"] - agg["start"])
                sp = "" if sport == "" else str(sport)
                dp = "" if dport == "" else str(dport)
                # 将 duration 转换为毫秒并保留 3 位小数
                duration_ms = duration * 1000
                writer.writerow([src, dst, proto, sp, dp, agg["bytes"], f"{duration_ms:.3f}"])

        print(f"Exported {len(capture_flows)} flows to {output_file}", flush=True)
        return True
    except Exception as e:
        print(f"Error writing CSV: {e}", flush=True)
        return False

def main():
    """Main capture loop"""
    if len(sys.argv) > 1:
        duration = int(sys.argv[1])
    else:
        duration = 30  # Default 30 seconds

    print(f"Starting packet capture for {duration} seconds...", flush=True)
    print("Press Ctrl+C to stop early", flush=True)

    try:
        # Capture packets for specified duration
        sniff(store=False, prn=on_packet, timeout=duration)
    except KeyboardInterrupt:
        print("\nCapture interrupted by user", flush=True)
    except Exception as e:
        print(f"Capture error: {e}", flush=True)

    # Write results
    write_csv()
    print("Capture completed", flush=True)

if __name__ == "__main__":
    main()
