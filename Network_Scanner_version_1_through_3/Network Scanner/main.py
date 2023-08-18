#This program is for the network scanner for my internship with Grab The Axe. Brandon Kling 6/3/2023

import scapy.all as scapy

def scan_network(ip):
    # Create an ARP request packet
    arp_request = scapy.ARP(pdst=ip)
    
    # Create an Ethernet broadcast packet
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Combine the ARP request and broadcast packets
    arp_request_broadcast = broadcast / arp_request
    
    # Send the combined packet and capture the response
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for element in answered_list:
        # Extract IP and MAC addresses from the response
        device = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        devices.append(device)
    
    return devices

def print_devices(devices):
    print("Devices connected to the network:")
    print("IP\t\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        # Print the IP and MAC addresses of the devices
        print(device["IP"] + "\t\t" + device["MAC"])

network_ip = "192.168.1.2/24"  # Update with your network IP range

devices = scan_network(network_ip)
print_devices(devices)