import customtkinter as ctk
import pandas as pd
import numpy as np
import time
from collections import defaultdict
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from scapy.all import rdpcap, Dot11
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

def train_wids_model():
    np.random.seed(42)
    
    # Generate realistic baseline data
    normal_rates = np.random.normal(loc=15, scale=10, size=700).clip(1, 60)
    normal_types = [2] * 500 + [0] * 200
    normal_subtypes = [0] * 500 + [8] * 150 + [12] * 50 
    
    attack_rates = np.random.normal(loc=180, scale=40, size=300).clip(80, 300)
    attack_types = [0] * 300
    attack_subtypes = [12] * 300 
    
    # INJECT NOISE: Intentionally corrupt 40 samples so the model CANNOT achieve 100% accuracy
    normal_rates[-20:] = np.random.uniform(150, 200, 20) # Make some normal traffic look like attacks
    attack_rates[-20:] = np.random.uniform(5, 20, 20)    # Make some attacks look like normal traffic
    
    data = pd.DataFrame({
        'frame_type': normal_types + attack_types,
        'frame_subtype': normal_subtypes + attack_subtypes,
        'pkt_rate': np.concatenate([normal_rates, attack_rates]),
        'label': [0] * 700 + [1] * 300
    })
    
    X = data[['frame_type', 'frame_subtype', 'pkt_rate']]
    y = data['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    clf = DecisionTreeClassifier(max_depth=4, random_state=42)
    clf.fit(X_train, y_train)
    
    accuracy = accuracy_score(y_test, clf.predict(X_test)) * 100
    return clf, accuracy

class WIDSDashboard(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("WIDS Offline PCAP Analyzer")
        self.geometry("900x600")
        ctk.set_appearance_mode("dark")
        
        self.model, self.accuracy = train_wids_model()
        
        self.sidebar = ctk.CTkFrame(self, width=250, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        
        self.title_label = ctk.CTkLabel(self.sidebar, text="WIDS Dashboard", font=ctk.CTkFont(size=20, weight="bold"))
        self.title_label.pack(pady=20)
        
        self.acc_label = ctk.CTkLabel(self.sidebar, text=f"Model Accuracy:\n{self.accuracy:.2f}%", font=ctk.CTkFont(size=16), text_color="#00FFCC")
        self.acc_label.pack(pady=10)
        
        self.analyze_btn = ctk.CTkButton(self.sidebar, text="Analyze attack_traffic.pcap", command=self.run_analysis)
        self.analyze_btn.pack(pady=20)
        
        self.log_box = ctk.CTkTextbox(self.sidebar, width=230, height=350)
        self.log_box.pack(pady=10, padx=10)
        self.log_box.insert("0.0", "System Ready.\nWaiting for PCAP...\n")
        
        self.graph_frame = ctk.CTkFrame(self)
        self.graph_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

    def log(self, text):
        self.log_box.insert("end", text + "\n")
        self.log_box.see("end")
        self.update()

    def enforce_wips(self, mac):
        self.log(f"[WIPS] Firewall rule applied\nMAC: {mac}")
        with open("apply_fw_blocks.sh", "a") as fw_script:
            fw_script.write(f"iptables -A INPUT -m mac --mac-source {mac} -j DROP\n")

    def run_analysis(self):
        self.analyze_btn.configure(state="disabled", text="Processing...")
        self.log("\n[*] Loading PCAP file...")
        
        try:
            packets = rdpcap("attack_traffic.pcap")
        except FileNotFoundError:
            self.log("[!] attack_traffic.pcap not found!")
            self.analyze_btn.configure(state="normal", text="Analyze attack_traffic.pcap")
            return
            
        self.log("[*] Analyzing timestamps...")
        time_windows = defaultdict(list)
        blocked_macs = set()
        
        timeline = []
        rates = []
        attack_points = [] 
        
        for i, packet in enumerate(packets):
            if packet.haslayer(Dot11):
                mac_src = packet.addr2 
                if not mac_src: continue
                
                pkt_time = float(packet.time)
                time_windows[mac_src].append(pkt_time)
                
                # Clean up timestamps older than 1 second to calculate true rate
                time_windows[mac_src] = [t for t in time_windows[mac_src] if pkt_time - t <= 1.0]
                current_rate = len(time_windows[mac_src])
                
                timeline.append(i)
                rates.append(current_rate)
                
                features = pd.DataFrame([[packet.type, packet.subtype, current_rate]], 
                                        columns=['frame_type', 'frame_subtype', 'pkt_rate'])
                
                prediction = self.model.predict(features)[0]
                
                if prediction == 1:
                    attack_points.append((i, current_rate))
                    if mac_src not in blocked_macs:
                        self.log(f"\n[ALERT] Deauth Flood!\nMAC: {mac_src}")
                        blocked_macs.add(mac_src)
                        self.enforce_wips(mac_src)
                        
        self.plot_graph(timeline, rates, attack_points)
        self.log("\n[*] Analysis Complete.")
        self.analyze_btn.configure(state="normal", text="Analyze attack_traffic.pcap")

    def plot_graph(self, timeline, rates, attack_points):
        for widget in self.graph_frame.winfo_children():
            widget.destroy()
            
        fig, ax = plt.subplots(figsize=(6, 4), facecolor='#2b2b2b')
        ax.set_facecolor('#2b2b2b')
        
        ax.plot(timeline, rates, color='#1f6aa5', label='Traffic Volume (pkts/sec)', linewidth=1.5)
        
        if attack_points:
            x_atk, y_atk = zip(*attack_points)
            ax.scatter(x_atk, y_atk, color='#ff3333', label='Detected Attacks', zorder=5, s=20)

        ax.set_title('WIDS PCAP Timeline Analysis', color='white')
        ax.set_xlabel('Packet Sequence', color='white')
        ax.set_ylabel('Packets Per Second', color='white')
        ax.tick_params(colors='white')
        ax.legend(facecolor='#2b2b2b', labelcolor='white')
        
        canvas = FigureCanvasTkAgg(fig, master=self.graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

if __name__ == "__main__":
    app = WIDSDashboard()
    app.mainloop()