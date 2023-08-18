# This is a test "network scanner" program for my internship with Grab the Axe. Brandon Kling 6/26/2023

import tkinter as tk
import nmap
import logging
import smtplib
from email.mime.text import MIMEText

# Configure logging
logging.basicConfig(filename='network_scan.log', level=logging.INFO,
                    format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

# GUI Setup
window = tk.Tk()
window.title("Network Scanner")
window.geometry("400x400")

result_text = tk.Text(window)
result_text.pack(fill=tk.BOTH, expand=True)

# Function to send an email
def send_email(subject, message, to):
    msg = MIMEText(message)
    msg['Subject'] = subject
    #replace with your email address
    msg['From'] = 'your-email@example.com'
    msg['To'] = to

    # Replace with your SMTP server details
    s = smtplib.SMTP('your-smtp-server.com')
    #replace with your username and password
    s.login('your-username', 'your-password')
    s.send_message(msg)
    s.quit()

# Function to determine if a device is suspicious
def is_suspicious(device):
    # Replace with your own logic to determine if a device is suspicious
    return False

# Dictionary mapping port numbers to services
port_services = {
    80: 'HTTP',
    443: 'HTTPS',
    22: 'SSH',
    # Add more ports and services as needed
}

# Function to scan the network
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
            result_text.insert(tk.END, f"IP Address: {ip_address} MAC Address: {mac_address}\n")

            # Log the device
            logging.info('Device: IP Address: %s MAC Address: %s' % (ip_address, mac_address))

            # Detect OS
            nm.scan(ip_address, arguments='-O')
            if 'osmatch' in nm[ip_address]:
                for osmatch in nm[ip_address]['osmatch']:
                    result_text.insert(tk.END, 'OS: %s Accuracy: %s\n' % (osmatch['name'], osmatch['accuracy']))
                    logging.info('OS: %s Accuracy: %s' % (osmatch['name'], osmatch['accuracy']))

            # Scan ports and services
            for port in port_services.keys():
                res = nm.scan(ip_address, str(port))
                res = res['scan']
                if res != {}:
                    res = res[list(res.keys())[0]]
                    if 'tcp' in res:
                        res = res['tcp']
                        if port in res:
                            res = res[port]
                            result_text.insert(tk.END, 'Port: %s State: %s Service: %s\n' % (port, res['state'], port_services[port]))
                            logging.info('Port: %s State: %s Service: %s' % (port, res['state'], port_services[port]))

            # Check if device is suspicious and send an email
            device = {
                'ip_address': ip_address,
                'mac_address': mac_address
            }
            if is_suspicious(device):
                # Set the to address to the email address of the administrator
                send_email('Suspicious device detected', str(device), 'admin@example.com')

# Button to start the network scan
scan_button = tk.Button(window, text="Scan Network", command=scan_network)
scan_button.pack()

# Start the GUI event loop
window.mainloop()