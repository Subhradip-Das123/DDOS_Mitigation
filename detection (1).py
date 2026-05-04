

from scapy.all import sniff, IP, TCP
import time
import logging
from collections import defaultdict
import psutil
import os


class Fmodel:
    def predict_proba(self, X):
        results = []
        for row in X:
            packets = row[0]

            if packets < 2:
                score = 0.3
            elif packets < 4:
                score = 0.6
            else:
                score = 0.95

            results.append([1-score, score])
        return results

# Try loading real model
MODEL_PATH = "ddos_detection_model.pkl"

try:
    import joblib
    model = joblib.load(MODEL_PATH)
    print("[INFO] ML model loaded")
except:
    print("[INFO] Using fallback model")
    model = Fmodel()

# ---- IMPORT MITIGATION ----
from mitigation import rate_limit_ip, block_ip

# ---- CONFIG ----
IFACE = "enp0s3"
WINDOW = 2

THRESH_MONITOR = 0.5
THRESH_RATE = 0.7

CRITICAL_DEVICES = ["192.168.56.20"]

# ---- LOGGING ----
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

# ---- STATE ----
packet_count = defaultdict(int)
syn_count = defaultdict(int)
start_time = time.time()
action_taken = {}

# ---- DETECTION ----

def detect(pkt):
    global start_time

    if IP not in pkt:
        return

    src = pkt[IP].src
    packet_count[src] += 1

    if TCP in pkt and pkt[TCP].flags == "S":
        syn_count[src] += 1

    now = time.time()

    if now - start_time >= WINDOW:

        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent

        for ip, count in packet_count.items():

            syns = syn_count.get(ip, 0)

            feature = [[count]]
            t1 = time.time()
            pred = model.predict_proba(feature)[0][1]
            t2 = time.time()

            latency = (t2 - t1) * 1000

            # ---- PRINT OUTPUT ----
            print("\n-----------------------------")
            print(f"IP: {ip}")
            print("Packets:", count)
            print("SYN:", syns)
            print("Risk Score:", pred)
            print("CPU:", cpu)
            print("RAM:", ram)
            print("Latency:", round(latency, 2), "ms")

            # ---- MITIGATION ----

            if ip in CRITICAL_DEVICES:
                print("[SAFE MODE]")
                continue

            prev = action_taken.get(ip)

            if pred < THRESH_MONITOR:
                print("[MONITOR]")

            elif pred < THRESH_RATE:
                print("[RATE LIMITED]")
                if prev != "rate":
                    rate_limit_ip(ip)
                    action_taken[ip] = "rate"

            else:
                print("[BLOCKED]")
                if prev != "block":
                    block_ip(ip)
                    action_taken[ip] = "block"

        packet_count.clear()
        syn_count.clear()
        start_time = now

# ---- START IDS ----

print(f"[START] Monitoring on {IFACE}...")

sniff(iface=IFACE, filter="ip", prn=detect, store=0)