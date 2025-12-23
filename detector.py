from logger import log_alert
from config import SUSPICIOUS_PORTS, PACKET_THRESHOLD, SEVERITY
from scapy.layers.inet import IP, TCP, UDP

packet_count = {}

def detect_intrusion(packet):
    # Only process IP packets
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    packet_count[src_ip] = packet_count.get(src_ip, 0) + 1

    # TCP traffic
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        if dst_port in SUSPICIOUS_PORTS:
            log_alert(
                SEVERITY["PORT_SCAN"],
                f"Suspicious TCP access from {src_ip} on port {dst_port}"
            )

    # UDP traffic
    if packet.haslayer(UDP):
        dst_port = packet[UDP].dport
        if dst_port in SUSPICIOUS_PORTS:
            log_alert(
                SEVERITY["PORT_SCAN"],
                f"Suspicious UDP access from {src_ip} on port {dst_port}"
            )

    # DoS detection (any protocol)
    if packet_count[src_ip] > PACKET_THRESHOLD:
        log_alert(
            SEVERITY["DOS"],
            f"Possible DoS attack from {src_ip}"
        )
