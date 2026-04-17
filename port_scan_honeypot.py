import scapy.all as scapy

fake_ip = "198.51.100.5"
target_ip = "172.16.99.216"

print(f"From {fake_ip} address, sending packet to port 23")

# scanning the port 23
paket = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.IP(src=fake_ip, dst=target_ip) / scapy.TCP(dport=23, flags="S")

scapy.sendp(paket, verbose=False)

print("Packet went")