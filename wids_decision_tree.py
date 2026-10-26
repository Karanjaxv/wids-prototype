import pandas as pd
import time
from collections import defaultdict
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.model_selection import train_test_split
from scapy.all import sniff, Dot11

def train_wids_model():
    print("[*] Training model with corrected realistic data...")
    
    # We now explicitly teach the model:
    # Subtype 12 @ 2-4 packets/sec = NORMAL (0)
    # Subtype 12 @ 300+ packets/sec = FLOOD ATTACK (1)
    data = {
        'frame_type':    [0, 0,  2,  2,  0,  0,   2,  0,  0,  0] * 100,
        'frame_subtype': [8, 8,  0,  0,  12, 12,  0,  8,  12, 12] * 100, 
        'pkt_rate':      [5, 10, 80, 60, 2,  300, 40, 75, 4,  310] * 100, 
        'label':         [0, 0,  0,  0,  0,  1,   0,  0,  0,  1] * 100
    }
    
    df = pd.DataFrame(data)
    X = df[['frame_type', 'frame_subtype', 'pkt_rate']]
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    clf = DecisionTreeClassifier(max_depth=4, random_state=42)
    clf.fit(X_train, y_train)
    
    print(f"[+] Model Accuracy: {accuracy_score(y_test, clf.predict(X_test)) * 100:.2f}%")
    return clf

def enforce_wips_block(mac_address):
    print(f"\n[WIPS] Initiating automated mitigation for Attacker MAC: {mac_address}")
    with open("apply_fw_blocks.sh", "a") as fw_script:
        fw_script.write(f"iptables -A INPUT -m mac --mac-source {mac_address} -j DROP\n")

packet_counts = defaultdict(int)
start_time = time.time()
blocked_macs = set()

def extract_and_predict(packet, model):
    global start_time, packet_counts, blocked_macs
    
    if packet.haslayer(Dot11):
        mac_src = packet.addr2 
        if not mac_src: return
        
        current_time = time.time()
        elapsed = current_time - start_time
        packet_counts[mac_src] += 1
        
        # Calculate rate every 1 second
        if elapsed >= 1.0:
            pkt_rate = packet_counts[mac_src] / elapsed
            features = pd.DataFrame([[packet.type, packet.subtype, pkt_rate]], 
                                    columns=['frame_type', 'frame_subtype', 'pkt_rate'])
            
            if model.predict(features)[0] == 1 and mac_src not in blocked_macs:
                print(f"[ALERT] Malicious Deauth Flood from {mac_src}! (Rate:{pkt_rate:.1f} p/s)")
                blocked_macs.add(mac_src)
                enforce_wips_block(mac_src)
            
            start_time = time.time()
            packet_counts.clear()

if __name__ == "__main__":
    trained_model = train_wids_model()
    # Change 'wlan0mon' to whatever your adapter is named after running airmon-ng start
    interface_name = "wlan0" 
    print(f"[*] Starting LIVE WIDS capture on {interface_name}...")
    try:
        # Live sniffing using the Wi-Fi adapter
        sniff(iface=interface_name, prn=lambda pkt: extract_and_predict(pkt, trained_model), store=False)
    except OSError:
        print(f"[!] Could not listen on {interface_name}. Run with sudo and check interface name.")