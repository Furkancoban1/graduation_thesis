import scapy.all as scapy
import time

fake_ip = "203.0.113.100"
target_ip = "172.16.99.216"

print(f"From{fake_ip} address, port scanning is being started")

# port scanning from port 20 to 45
for port in range(30, 55):
    packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.IP(src=fake_ip, dst=target_ip) / scapy.TCP(dport=port, flags="S")
    scapy.sendp(packet, verbose=False)
    time.sleep(0.05)

print("Scanning is completed")