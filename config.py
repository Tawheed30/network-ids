# IDS configuration

SUSPICIOUS_PORTS = [21, 22, 23, 3389]
PACKET_THRESHOLD = 100

SEVERITY = {
    "PORT_SCAN": "HIGH",
    "DOS": "CRITICAL"
}

LOG_FILE = "sample_logs/alerts.log"
