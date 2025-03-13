import tkinter as tk
from tkinter import ttk
from ttkbootstrap import Style
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import time

# Initialize theme
style = Style(theme="darkly")  # Other options: "cosmo", "cyborg", "superhero"

# Known malicious IPs for simple Intrusion Detection
malicious_ips = ["192.168.1.100", "10.10.10.10"]

# Main Window Setup
root = style.master
root.title("Advanced Network Packet Analyzer")
root.geometry("900x500")  # Set window size

# Status Bar
status_var = tk.StringVar()
status_var.set("Status: Ready")

status_bar = ttk.Label(root, textvariable=status_var, anchor="w", padding=5, font=("Arial", 10))
status_bar.pack(fill=tk.X, side=tk.BOTTOM)

# Frame Layout
main_frame = ttk.Frame(root, padding=10)
main_frame.pack(fill=tk.BOTH, expand=True)

# Packet Table
columns = ("Source IP", "Destination IP", "Protocol", "Payload", "Alert")
tree = ttk.Treeview(main_frame, columns=columns, show="headings", height=15)

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=150, anchor="center")

tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

# Apply alternating row colors
def update_row_colors():
    for i, item in enumerate(tree.get_children()):
        tree.item(item, tags=("evenrow" if i % 2 == 0 else "oddrow"))
    tree.tag_configure("evenrow", background="#2E2E2E")  # Dark gray
    tree.tag_configure("oddrow", background="#3A3A3A")   # Slightly lighter gray

# Sidebar for Controls
sidebar = ttk.Frame(main_frame, padding=10)
sidebar.pack(side=tk.RIGHT, fill=tk.Y)

# Packet Filter Options
filter_var = tk.StringVar()
filter_var.set("All")

ttk.Label(sidebar, text="Filter by Protocol:", font=("Arial", 11)).pack(pady=5)

filter_options = ["All", "TCP", "UDP", "ICMP"]
filter_menu = ttk.Combobox(sidebar, textvariable=filter_var, values=filter_options, state="readonly")
filter_menu.pack(pady=5)

# Start/Stop Buttons
is_sniffing = False

def detect_intrusion(packet):
    """Detects suspicious activity based on packet details."""
    alert_msg = ""

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Check for known malicious IPs
        if src_ip in malicious_ips or dst_ip in malicious_ips:
            alert_msg = "⚠️ Malicious IP Detected!"

        # Detect unusually high traffic (Simple Flood Detection)
        current_time = time.time()
        if detect_intrusion.last_packet_time:
            time_diff = current_time - detect_intrusion.last_packet_time
            if time_diff < 0.1:
                alert_msg = "🚨 Possible DDoS Attack!"

        detect_intrusion.last_packet_time = current_time
    return alert_msg

detect_intrusion.last_packet_time = None

def packet_callback(packet):
    """Processes and displays captured packets."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP" if packet.haslayer(ICMP) else "Other"
        payload = bytes(packet.payload)[:20]

        selected_filter = filter_var.get()
        if selected_filter != "All" and selected_filter != protocol:
            return  # Ignore packets that don't match filter

        alert = detect_intrusion(packet)

        tree.insert("", tk.END, values=(src_ip, dst_ip, protocol, payload, alert))
        update_row_colors()

def start_sniffing():
    """Starts packet sniffing in a separate thread."""
    global is_sniffing
    is_sniffing = True
    status_var.set("Status: Sniffing... 🟢")

    selected_filter = filter_var.get().lower()
    bpf_filter = None

    if selected_filter == "tcp":
        bpf_filter = "tcp"
    elif selected_filter == "udp":
        bpf_filter = "udp"
    elif selected_filter == "icmp":
        bpf_filter = "icmp"

    sniff_args = {"prn": packet_callback, "store": False}
    if bpf_filter:
        sniff_args["filter"] = bpf_filter

    threading.Thread(target=lambda: sniff(**sniff_args), daemon=True).start()

def stop_sniffing():
    """Stops packet sniffing."""
    global is_sniffing
    is_sniffing = False
    status_var.set("Status: Stopped ❌")

# Buttons
start_btn = ttk.Button(sidebar, text="Start Sniffing", command=start_sniffing, bootstyle="success")
start_btn.pack(pady=10, fill=tk.X)

stop_btn = ttk.Button(sidebar, text="Stop Sniffing", command=stop_sniffing, bootstyle="danger")
stop_btn.pack(pady=5, fill=tk.X)

# Run the GUI
root.mainloop()