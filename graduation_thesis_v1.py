import scapy.all as scapy
import time
import logging
import subprocess
import ctypes
from collections import defaultdict

# Parameters
syn_threshold = 150  # Max packet number before blocking
time_limit = 1  # Time for counting packets

port_threshold = 15
port_window = 5
honeypot = 23

behavior_timeout = 10  # Max seconds allowed to complete an HTTP request

# Denied words for sql injection
DPI_SIGNATURES = [
    "union select",
    "or 1=1",
    "etc/passwd",
    "<script>",
    "cmd.exe"
]

blocked_ips = set()
whitelist = ("192.168.", "10.", "127.0.0.1")  # Ips not to block

# Saves the attacks and system notifications to txt file
logging.basicConfig(filename="ips_log.txt",
                    level=logging.INFO,
                    format="%(asctime)s - %(message)s")

packet_history = defaultdict(list)
port_history = defaultdict(list)
http_tracker = defaultdict(lambda: {"start_time": 0, "data": ""})


# Pop-up message appears to show that an specific IP banned, it is used by block_ip function
def give_alert(title, msg):
    ctypes.windll.user32.MessageBoxW(0, msg, title, 0x30)


def is_whitelisted(ip):
    return ip.startswith(whitelist)


# Blocks the attacker
def block_ip(ip):
    if ip in blocked_ips:
        return

    print(f"IP is blocking: {ip}")
    cmd = f'netsh advfirewall firewall add rule name="IPS_Block_{ip}" dir=in action=block remoteip={ip}'

    try:
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        blocked_ips.add(ip)
        logging.info(f"Blocked: {ip}")
        print(f" {ip} is being added to firewall.")
        give_alert("IPS alert", f"Attack is detected and ip is blocked. IP: {ip}")
    except subprocess.CalledProcessError:
        print(f"Error: {ip} couldn't banned.")


# Proccess the each packet, if it detects an attacker it will pass the ip to block_ip function
def process_packet(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        current_time = time.time()

        if is_whitelisted(src_ip):
            return

        # Check for malicious payloads (DPI) and Behavioral Analysis
        if packet.haslayer(scapy.Raw):
            try:
                payload = packet[scapy.Raw].load.decode(errors='ignore').lower()

                # 1. DPI Engine (Signature Matching)
                for signature in DPI_SIGNATURES:
                    if signature in payload and src_ip not in blocked_ips:
                        msg = f"\nDPI alert, malicious payload from: {src_ip}"
                        print(msg)
                        logging.info(msg)
                        block_ip(src_ip)
                        return

                # 2. Behavioral Analysis Engine (Low and Slow / Slowloris Detection)
                if packet.haslayer(scapy.TCP):
                    dport = packet[scapy.TCP].dport
                    if dport == 80 or dport == 443: # Checking web traffic
                        if http_tracker[src_ip]["start_time"] == 0:
                            http_tracker[src_ip]["start_time"] = current_time

                        http_tracker[src_ip]["data"] += payload

                        # If request completes with standard HTTP ending, reset tracker
                        if "\r\n\r\n" in http_tracker[src_ip]["data"]:
                            http_tracker[src_ip] = {"start_time": 0, "data": ""}
                        else:
                            # Incomplete request: check if it exceeds the behavior timeout
                            if current_time - http_tracker[src_ip]["start_time"] > behavior_timeout:
                                if src_ip not in blocked_ips:
                                    msg = f"\nBehavioral alert, slow HTTP attack from: {src_ip}"
                                    print(msg)
                                    logging.info(msg)
                                    block_ip(src_ip)
                                    return
            except Exception:
                pass

        if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
            dport = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else packet[scapy.UDP].dport

            # Honeypot trigger
            if dport == honeypot and src_ip not in blocked_ips:
                msg = f"\nHoneypot trigger detected, source: {src_ip}"
                print(msg)
                logging.info(msg)
                block_ip(src_ip)
                return

            # Port scan detection
            port_history[src_ip] = [(p, t) for (p, t) in port_history[src_ip] if current_time - t <= port_window]
            port_history[src_ip].append((dport, current_time))
            unique_ports = set([p for (p, t) in port_history[src_ip]])

            if len(unique_ports) > port_threshold and src_ip not in blocked_ips:
                msg = f"\nPort scan is detected, source: {src_ip}"
                print(msg)
                logging.info(msg)
                block_ip(src_ip)
                return

        # SYN flood detection
        packet_history[src_ip] = [t for t in packet_history[src_ip] if current_time - t <= time_limit]
        packet_history[src_ip].append(current_time)

        if len(packet_history[src_ip]) > syn_threshold and src_ip not in blocked_ips:
            print(f"\nSYN Flood is detected, source: {src_ip}")
            block_ip(src_ip)

def start_sniffing():
    print("Mini-IPS is active. It is listening the network.")
    scapy.sniff(store=False, prn=process_packet)


if __name__ == "__main__":
    start_sniffing()
