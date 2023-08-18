#This is a test network scanner program to try and detect devices on the network and disable/disconnect them. Brandon Kling 6/11/2023

import nmap
import tkinter as tk
from tkinter import messagebox

def scan_network():
    # Clear previous results
    result_text.delete("1.0", tk.END)
    
    # Create an instance of the PortScanner class
    nm = nmap.PortScanner()

    # Scan the network for devices
    nm.scan(hosts='192.168.0.0/24', arguments='-sn')

    # Iterate over all the scanned hosts
    for host in nm.all_hosts():
        if 'mac' in nm[host]['addresses']:
            mac_address = nm[host]['addresses']['mac']
            ip_address = nm[host]['addresses']['ipv4']
            result_text.insert(tk.END, f"IP Address: {ip_address}   MAC Address: {mac_address}\n")

def disconnect_device():
    # Placeholder till I can figure out how to disconnect a device legally
    # Implement your code to disconnect the unwanted device here
    messagebox.showinfo("Disconnect", "Device disconnected!")

# Create the main window
window = tk.Tk()
window.title("Network Scanner")

# Create UI elements
scan_button = tk.Button(window, text="Scan Network", command=scan_network)
scan_button.pack(pady=10)

disconnect_button = tk.Button(window, text="Disconnect Device", command=disconnect_device)
disconnect_button.pack(pady=10)

result_text = tk.Text(window, height=10, width=50)
result_text.pack(pady=10)

# Start the main loop
window.mainloop()