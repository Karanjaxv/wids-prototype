from scapy.all import Dot11, wrpcap
import random
import time

print("[*] Forging highly realistic, RANDOMIZED Wi-Fi traffic PCAP...")
packets = []

target_bssid = "6E:A7:8F:12:8F:25" 
# Dynamically generate a random attacker MAC address each time
attacker_mac = f"74:83:C2:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}"
normal_macs = ["40:9C:28:11:22:33", "00:1A:73:44:55:66", "D4:53:2A:61:CB:75"]

# 1. Randomize the amount of normal background traffic (between 100 and 500 packets)
normal_count = random.randint(100, 500)
base_time = time.time()
for i in range(normal_count):
    mac = random.choice(normal_macs)
    pkt = Dot11(type=2, subtype=0, addr1=target_bssid, addr2=mac, addr3=target_bssid)
    pkt.time = base_time + (i * random.uniform(0.01, 0.08)) 
    packets.append(pkt)

# 2. Normal slow disconnects
for i in range(random.randint(2, 6)):
    mac = random.choice(normal_macs)
    pkt = Dot11(type=0, subtype=12, addr1=target_bssid, addr2=mac, addr3=target_bssid)
    pkt.time = base_time + 5.0 + (i * 2.0)
    packets.append(pkt)

# 3. Randomize the attack size (between 250 and 800 packets) and speed
attack_count = random.randint(250, 800)
attack_speed = random.uniform(0.001, 0.004)
print(f"[*] Injecting Deauth flood ({attack_count} packets) from MAC: {attacker_mac}")
attack_start_time = packets[-1].time + 1.5
for i in range(attack_count): 
    pkt = Dot11(type=0, subtype=12, addr1="FF:FF:FF:FF:FF:FF", addr2=attacker_mac, addr3=target_bssid)
    pkt.time = attack_start_time + (i * attack_speed) 
    packets.append(pkt)

file_name = "attack_traffic.pcap"
wrpcap(file_name, packets)
print(f"[+] Saved {len(packets)} timestamped packets to {file_name}")