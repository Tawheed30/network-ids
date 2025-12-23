from scapy.all import sniff
from detector import detect_intrusion

print(">>> IDS process started <<<", flush=True)

def start_ids():
    print(">>> Sniffing on en0 <<<", flush=True)
    sniff(iface="en0", prn=detect_intrusion, store=False)

if __name__ == "__main__":
    start_ids()

