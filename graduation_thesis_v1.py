import scapy.all as scapy
import time
import logging
import subprocess
import ctypes
from collections import defaultdict

# Parameters
threshold = 999 #Max packet number before blocking
time_limit = 1 #Time for counting packets
blocked_ips = set()
whitelist = ("10.", "127.0.0.1", "192.168.") # Ips not to block

# Saves the attacks and system notifications to txt file
logging.basicConfig(filename="ips_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")
packet_history = defaultdict(list)

# Pop-up message appears to show that an specific IP banned, it is used by block_ip function
def give_alert(title, msg):
    ctypes.windll.user32.MessageBoxW(0, msg, title, 0x30)

# Blocks the attacker
def block_ip(ip):
    if ip in blocked_ips:
        return

    print(f"IP is blocking: {ip}")
    cmd = f'netsh advfirewall firewall add rule name="IPS_Block_{ip}" dir=in action=block remoteip={ip}'

    try:
        # CMD çıktısını gizle, sadece çalıştır
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        blocked_ips.add(ip)
        logging.info(f"Blocked: {ip}")
        print(f" {ip} is being added to firewall.")
        give_alert("IPS alert", f"Attack is detected and ip is blocked. IP: {ip}")
    except Exception:
        print(f"Error: {ip} couldn't banned.")

# Proccess the each packet, if it detects an attacker it will pass the ip to block_ip function
def process_packet(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src

        if src_ip.startswith(whitelist):
            return

        current_time = time.time()
        packet_history[src_ip] = [t for t in packet_history[src_ip] if current_time - t <= time_limit]
        packet_history[src_ip].append(current_time)

        if len(packet_history[src_ip]) > threshold and src_ip not in blocked_ips:
            print(f"\nSYN Flood is detected, source: {src_ip}")
            block_ip(src_ip)


if __name__ == "__main__":
    print("Mini-IPS is active. It is listening the network.")
    scapy.sniff(store=False, prn=process_packet)