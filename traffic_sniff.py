# Author: Jose Bianchi 
# Description: Program to send an alert json message with a timestamp and eventDescription key 
#   to url_notify, if it flags suspicious activity on the network, including use of unsecure 
#   protocols, requests with malformed packets, or requests to known malicious sites. 
#   The program also writes to a local log .txt file how many inspections it has completed 
#   and how many instances of suspicious activity found. 


import os
import json
import requests
import time
from datetime import datetime
from scapy.all import sniff
import re
from scapy.layers.http import HTTPRequest
from credentials import url_notify
from credentials import flagged_ips


unsafe_protocols = {
    23: 'Telnet',
    21: 'FTP',
    80: 'HTTP',
    25: 'SMTP',
    53: 'DNS'
}

def check_unsafe_protocol(result_dict):
    unsafe = False
    event_description = 'Unsafe protocol detected: '
    if 'Protocol' in result_dict:
        protocol = result_dict['Protocol']
        if 'Source_Port' in result_dict:
            source_port = result_dict['Source_Port']
            if source_port in unsafe_protocols:
                unsafe = True
                event_description += f"{unsafe_protocols[source_port]} at source port {source_port}. "
        if 'Destination_Port' in result_dict:
            dest_port = result_dict['Destination_Port']
            if dest_port in unsafe_protocols:
                unsafe = True
                event_description += f"{unsafe_protocols[dest_port]} at destination port {dest_port}"
    if unsafe:
        return event_description
    return None


def check_malformed_packet(result_dict):
    unsafe = False
    event_description = 'Malformed packet: '
    if 'Source_IP' not in result_dict or 'Destination_IP' not in result_dict:
        unsafe = True
        event_description += "Missing source or destination IP. "
    
    if 'Protocol' not in result_dict:
        unsafe = True
        event_description += "Missing protocol. "
    
    # Check for other missing layers based on your expected structure
    if 'Source_Port' not in result_dict or 'Destination_Port' not in result_dict:
        unsafe = True
        event_description += "Missing source or destination port."
    
    if unsafe:
        return event_description
    return None


def check_flagged_site(result_dict):
    unsafe = False
    event_description = ''
    if 'Destination_IP' in result_dict:
        dest_ip = result_dict['Destination_IP']
        if dest_ip in flagged_ips:
            unsafe = True
            event_description += f"Flagged site accessed: {dest_ip}"
    if unsafe:
        return event_description
    return None


# Function to send alert message
def send_alert(event_description, packet):
    alert_data = {
        "timestamp": datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
        "eventDescription": event_description,
        "source": "Traffic Packet Analyzer",
        "packetData": packet
    }
    try:
        response = requests.post(url_notify, json=alert_data)
        if response.status_code == 200:
            print(f"Alert sent successfully: {alert_data}")
        else:
            print(f"Failed to send alert. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending alert: {e}")


# Function to log activity to a file
def log_activity(file_path, suspicious_packet=False):
    """
    Updates local log file. Always adds 1 to inspection count.
    Adds 1 to suspicious count if argument is True.
    """
    inspections_completed = 0
    suspicious_count = 0
    # Write file template if empty
    if os.path.getsize(file_path) == 0:
        line1 = "Packet Inspections Completed: 0"
        line2 = "Suspicious Packets Found: 0"
        # Open the file and write str1 and str2
        with open(file_path, 'w') as file:
            file.write(line1 + "\n" + line2)
    
    # Get counts
    with open(file_path, 'r') as file:
        lines = file.readlines()  
        line1_parts = lines[0].split(":")  
        inspections_completed = int(line1_parts[1].strip())  
        line2_parts = lines[1].split(":")  
        suspicious_count = int(line2_parts[1].strip())  
    
    # Update counts in log
    inspections_completed += 1
    if suspicious_packet:
        suspicious_count += 1
    newline1 = f"Packet Inspections Completed: {inspections_completed}"
    newline2 = f"Suspicious Packets Found: {suspicious_count}"
    # Open the file in write mode, which overwrites the file's contents
    with open(file_path, 'w') as file:
        file.write(newline1 + "\n" + newline2)



# Main function
def main():
    log_file = "traffic_log.txt"

    def process_packet(packet):
        print(packet.summary())
        # Create a dictionary to store parsed data for each packet
        result_dict = {}

        # Check if the packet has an Ethernet, IP, and UDP layer
        if packet.haslayer('Ether'):
            result_dict['Ethernet'] = packet.getlayer('Ether').type

        if packet.haslayer('IP'):
            result_dict['IP'] = packet.getlayer('IP').proto
            result_dict['Source_IP'] = packet.getlayer('IP').src
            result_dict['Destination_IP'] = packet.getlayer('IP').dst

        if packet.haslayer('UDP'):
            result_dict['Protocol'] = 'UDP'
            result_dict['Source_Port'] = packet.getlayer('UDP').sport
            result_dict['Destination_Port'] = packet.getlayer('UDP').dport

        # Add additional information, such as "Raw" or other info if needed
        result_dict['Raw'] = packet.summary()

        event_msg = ''
        # Check for unsafe protocols
        unsafe_protocol = check_unsafe_protocol(result_dict)
        if unsafe_protocol:
            event_msg += unsafe_protocol + ' '

        # Check for malformed packets
        malformed_packet = check_malformed_packet(result_dict)
        if malformed_packet:
            event_msg += malformed_packet + ' '

        # Check if a flagged site is accessed
        flagged_site = check_flagged_site(result_dict)
        if flagged_site:
            event_msg += flagged_site + ' '

        if event_msg != '':
            print('issue found')
            log_activity(log_file, True)
            packet_str = f"{result_dict}"
            send_alert(event_msg, packet_str)
        else:
            # Update log to add 1 just to inspected
            print('safe')
            log_activity(log_file)

    # Start sniffing packets and process them
    sniff(count=100, prn=process_packet, store=0)

if __name__ == '__main__':
    while True:
        main()
        time.sleep(60)
