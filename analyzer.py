import os
from collections import Counter, defaultdict
from typing import Dict, List, Any

import pandas as pd
import pyshark
from sklearn.ensemble import IsolationForest


TSHARK_PATH = "/Applications/Wireshark.app/Contents/MacOS/tshark"


def get_tshark_path() -> str | None:
    """
    On macOS, Wireshark often stores tshark here:
    /Applications/Wireshark.app/Contents/MacOS/tshark

    If that exists, use it.
    Otherwise, let PyShark try to find tshark from PATH.
    """
    if os.path.exists(TSHARK_PATH):
        return TSHARK_PATH
    return None


def safe_getattr(obj, attr: str, default=None):
    """
    Safely get an attribute from a PyShark packet/layer.
    PyShark fields vary depending on the packet protocol.
    """
    try:
        return getattr(obj, attr)
    except Exception:
        return default


def extract_packets_from_pcap(file_path: str, max_packets: int = 2000) -> List[Dict[str, Any]]:
    """
    Reads packets from a saved .pcap or .pcapng file using PyShark.
    This does NOT do live capture.
    """
    packets_data = []

    tshark_path = get_tshark_path()

    if tshark_path:
        capture = pyshark.FileCapture(
            file_path,
            tshark_path=tshark_path,
            keep_packets=False
        )
    else:
        capture = pyshark.FileCapture(
            file_path,
            keep_packets=False
        )

    try:
        for index, packet in enumerate(capture):
            if index >= max_packets:
                break

            packet_info = {
                "number": index + 1,
                "timestamp": str(safe_getattr(packet, "sniff_time", "")),
                "length": int(safe_getattr(packet, "length", 0) or 0),
                "highest_layer": safe_getattr(packet, "highest_layer", "UNKNOWN"),
                "transport_layer": safe_getattr(packet, "transport_layer", "UNKNOWN"),
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "protocol": safe_getattr(packet, "highest_layer", "UNKNOWN"),
            }

            # IP layer
            if hasattr(packet, "ip"):
                packet_info["src_ip"] = safe_getattr(packet.ip, "src", None)
                packet_info["dst_ip"] = safe_getattr(packet.ip, "dst", None)

            # IPv6 layer
            elif hasattr(packet, "ipv6"):
                packet_info["src_ip"] = safe_getattr(packet.ipv6, "src", None)
                packet_info["dst_ip"] = safe_getattr(packet.ipv6, "dst", None)

            # TCP layer
            if hasattr(packet, "tcp"):
                packet_info["src_port"] = safe_getattr(packet.tcp, "srcport", None)
                packet_info["dst_port"] = safe_getattr(packet.tcp, "dstport", None)
                packet_info["protocol"] = "TCP"

            # UDP layer
            elif hasattr(packet, "udp"):
                packet_info["src_port"] = safe_getattr(packet.udp, "srcport", None)
                packet_info["dst_port"] = safe_getattr(packet.udp, "dstport", None)
                packet_info["protocol"] = "UDP"

            # ICMP layer
            elif hasattr(packet, "icmp"):
                packet_info["protocol"] = "ICMP"

            packets_data.append(packet_info)

    finally:
        capture.close()

    return packets_data


def build_summary(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Creates readable statistics from the packet list.
    """
    total_packets = len(packets)
    total_bytes = sum(packet["length"] for packet in packets)

    protocol_counter = Counter(packet["protocol"] for packet in packets)
    src_ip_counter = Counter(packet["src_ip"] for packet in packets if packet["src_ip"])
    dst_ip_counter = Counter(packet["dst_ip"] for packet in packets if packet["dst_ip"])
    dst_port_counter = Counter(packet["dst_port"] for packet in packets if packet["dst_port"])

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "protocols": protocol_counter.most_common(10),
        "top_source_ips": src_ip_counter.most_common(10),
        "top_destination_ips": dst_ip_counter.most_common(10),
        "top_destination_ports": dst_port_counter.most_common(10),
    }


def detect_anomalies(packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Uses Isolation Forest to flag unusual packets.

    This is a basic AI anomaly detector.
    It looks at:
    - packet length
    - whether protocol is TCP
    - whether protocol is UDP
    - source port
    - destination port

    It is not a full cybersecurity AI yet, but it gives you a real starting point.
    """
    if len(packets) < 10:
        return []

    rows = []

    for packet in packets:
        src_port = packet.get("src_port")
        dst_port = packet.get("dst_port")

        try:
            src_port = int(src_port) if src_port else 0
        except ValueError:
            src_port = 0

        try:
            dst_port = int(dst_port) if dst_port else 0
        except ValueError:
            dst_port = 0

        protocol = packet.get("protocol", "UNKNOWN")

        rows.append({
            "length": packet.get("length", 0),
            "is_tcp": 1 if protocol == "TCP" else 0,
            "is_udp": 1 if protocol == "UDP" else 0,
            "src_port": src_port,
            "dst_port": dst_port,
        })

    df = pd.DataFrame(rows)

    model = IsolationForest(
        contamination=0.08,
        random_state=42
    )

    predictions = model.fit_predict(df)

    anomalies = []

    for packet, prediction in zip(packets, predictions):
        if prediction == -1:
            anomalies.append(packet)

    return anomalies[:50]


def generate_security_notes(summary: Dict[str, Any], anomalies: List[Dict[str, Any]]) -> List[str]:
    """
    Generates simple human-readable security notes.
    """
    notes = []

    if summary["total_packets"] == 0:
        notes.append("No packets were found in this capture.")
        return notes

    notes.append(f"The capture contains {summary['total_packets']} packets and {summary['total_bytes']} total bytes.")

    protocols = [item[0] for item in summary["protocols"]]

    if "TCP" in protocols:
        notes.append("TCP traffic was detected. This is normal for web traffic, local apps, and many network services.")

    if "UDP" in protocols:
        notes.append("UDP traffic was detected. This may be normal for DNS, streaming, discovery protocols, or local services.")

    if "ICMP" in protocols:
        notes.append("ICMP traffic was detected. This is commonly related to ping or network diagnostics.")

    if len(anomalies) > 0:
        notes.append(f"The anomaly model flagged {len(anomalies)} packets as unusual based on size, protocol, and port behavior.")
    else:
        notes.append("The anomaly model did not flag unusual packets in this capture.")

    top_ports = summary.get("top_destination_ports", [])
    interesting_ports = {"22": "SSH", "23": "Telnet", "80": "HTTP", "443": "HTTPS", "3389": "Remote Desktop"}

    for port, count in top_ports:
        port_str = str(port)
        if port_str in interesting_ports:
            notes.append(f"Destination port {port_str} appeared {count} times. This is commonly associated with {interesting_ports[port_str]}.")

    return notes


def analyze_pcap(file_path: str) -> Dict[str, Any]:
    """
    Main function used by the FastAPI app.
    """
    packets = extract_packets_from_pcap(file_path)
    summary = build_summary(packets)
    anomalies = detect_anomalies(packets)
    notes = generate_security_notes(summary, anomalies)

    return {
        "summary": summary,
        "anomalies": anomalies,
        "notes": notes,
        "sample_packets": packets[:100],
    }