import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP, send
import threading
import ctypes
import os
from ipwhois import IPWhois

# Firewall rules
firewall_rules = []
packet_count = {}
sniff_thread = None
sniff_running = False
rules_file = "firewall_rules.txt"

# Load firewall rules from a file
def load_rules():
    if os.path.exists(rules_file):
        with open(rules_file, "r") as f:
            return [line.strip() for line in f.readlines()]
    return []

# Save firewall rules to a file
def save_rules():
    with open(rules_file, "w") as f:
        for rule in firewall_rules:
            f.write(rule + "\n")

# Add a rule to block connections to a specific host
def add_rule(host):
    if host not in firewall_rules:
        firewall_rules.append(host)
        save_rules()

# Remove a rule
def remove_rule(host):
    if host in firewall_rules:
        firewall_rules.remove(host)
        save_rules()

# Function to get the organization name from an IP
def get_organization(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        org_name = res.get('network', {}).get('name', 'Unknown Organization')
        return org_name
    except Exception:
        return "Unknown Organization"

# Send a payload "TRY HARDER" to the blocked host
def send_payload(dst_ip):
    ip = IP(dst=dst_ip)
    tcp = TCP(dport=80, flags="S", seq=1000, ack=0)
    payload = b"TRY HARDER"
    packet = ip/tcp/payload
    send(packet)

# Analyze packets in real-time
def analyze_packet(packet):
    global packet_count

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"

        flags = "None"
        if TCP in packet:
            if packet[TCP].flags & 0x02:
                flags = "SYN"
            elif packet[TCP].flags & 0x10:
                flags = "ACK"
            elif packet[TCP].flags & 0x12:
                flags = "SYN+ACK"
            elif packet[TCP].flags & 0x01:
                flags = "FIN"
            elif packet[TCP].flags & 0x04:
                flags = "RST"
            else:
                flags = "OTHER"

        org_name = get_organization(dst)

        if dst not in packet_count:
            packet_count[dst] = 0
        packet_count[dst] += 1

        for rule in firewall_rules:
            if dst == rule:
                print(f"Blocked packet to {dst} ({org_name}) (SYN or other) with payload: TRY HARDER")
                send_payload(dst)
                return

        connection_details = f"Packet: {src} -> {dst} [{proto}] [{flags}] [{org_name}]"
        print(connection_details)
        listbox_connections.insert(tk.END, connection_details)
        listbox_connections.yview(tk.END)

# Function to start sniffing
def start_sniffing():
    global sniff_running
    sniff_running = True
    sniff(filter="ip", prn=analyze_packet, store=0)

# Function to stop sniffing
def stop_sniffing():
    global sniff_running
    sniff_running = False
    if sniff_thread:
        ctypes.windll.kernel32.TerminateThread(ctypes.c_int(sniff_thread.ident), 0)

# GUI functionality
def start_firewall():
    global sniff_thread
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

def stop_firewall():
    stop_sniffing()

def add_firewall_rule():
    host = entry_rule.get()
    if host:
        add_rule(host)
        listbox_rules.insert(tk.END, host)
        entry_rule.delete(0, tk.END)

def remove_firewall_rule():
    selected_host = listbox_rules.get(tk.ANCHOR)
    if selected_host:
        remove_rule(selected_host)
        listbox_rules.delete(tk.ANCHOR)

# GUI Design
root = tk.Tk()
root.title("No Intrude by Andrew")

frame_top = ttk.Frame(root)
frame_top.pack(pady=10, padx=10)

label_rule = ttk.Label(frame_top, text="Block IP Host:")
label_rule.grid(row=0, column=0, padx=5)

entry_rule = ttk.Entry(frame_top)
entry_rule.grid(row=0, column=1, padx=5)

button_add_rule = ttk.Button(frame_top, text="Add Rule", command=add_firewall_rule)
button_add_rule.grid(row=0, column=2, padx=5)

button_remove_rule = ttk.Button(frame_top, text="Remove Rule", command=remove_firewall_rule)
button_remove_rule.grid(row=0, column=3, padx=5)

listbox_rules = tk.Listbox(root, height=10, width=50)
listbox_rules.pack(pady=10)

button_start = ttk.Button(root, text="Start", command=start_firewall)
button_start.pack(pady=5)

button_stop = ttk.Button(root, text="Stop", command=stop_firewall)
button_stop.pack(pady=5)

firewall_rules = load_rules()
for rule in firewall_rules:
    listbox_rules.insert(tk.END, rule)

frame_connections = ttk.Frame(root)
frame_connections.pack(pady=10)

label_connections = ttk.Label(frame_connections, text="Active Connections:")
label_connections.grid(row=0, column=0, padx=5)

scrollbar = ttk.Scrollbar(frame_connections, orient="vertical")
scrollbar.grid(row=1, column=1, sticky="ns")

listbox_connections = tk.Listbox(frame_connections, height=10, width=80, yscrollcommand=scrollbar.set)
listbox_connections.grid(row=1, column=0, padx=5)

scrollbar.config(command=listbox_connections.yview)

root.mainloop()
