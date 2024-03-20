import subprocess
import sys
import time
import requests
import yaml
import platform as plat
from scapy.all import *

# Global variables to track suspicious activity and related information
suspicious_activity_detected = False
suspicious_ips = set()
source_dest_pairs = []

# Function to load configuration from YAML file
def load_config(file_path):
    try:
        with open(file_path, 'r') as file:
            config = yaml.safe_load(file)
        return config
    except FileNotFoundError:
        print("Configuration file not found.")
        sys.exit(1)
    except yaml.YAMLError as e:
        print("Error parsing configuration file:", e)
        sys.exit(1)

# Function to fetch information from IPInfo API for a given IP address
def ipinfo_city(ip_address, api_key):
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json?token={api_key}")
        response.raise_for_status()  # Raises an error for 4xx or 5xx status codes
        data = response.json()
        city = data.get('city')
        region = data.get('region')
        country = data.get('country')
        loc = data.get('loc')
        if loc:
            latitude, longitude = loc.split(',')
            return {
                "ip": ip_address,
                "city": city,
                "region": region,
                "country": country,
                "latitude": latitude,
                "longitude": longitude
            }
        else:
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error fetching location for {ip_address}: {e}")
        return None

# Function to send notification
def send_notification(message):
    global suspicious_activity_detected
    if not suspicious_activity_detected:
        suspicious_activity_detected = True
        if plat.system() == 'Linux':
            subprocess.Popen(['notify-send', 'Suspicious Activity Detected', message])
            subprocess.Popen(['paplay', '/usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga'])
        elif plat.system() == 'Windows':
            from win10toast import ToastNotifier
            toaster = ToastNotifier()
            toaster.show_toast("Suspicious Activity Detected", message, duration=10)
            # Play sound on Windows
            import winsound
            winsound.PlaySound("SystemExclamation", winsound.SND_ALIAS)
        else:
            print("Unsupported operating system.")

# Function to perform analysis on the captured network traffic
def perform_analysis(config):
    global suspicious_ips, source_dest_pairs
    blacklisted_ips = set()

    def packet_callback(packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst

            if ip_src in config['black_listed_ip']:
                blacklisted_ips.add(ip_src)
                suspicious_ips.add(ip_dst)
                source_dest_pairs.append((ip_src, ip_dst))
            elif ip_dst in config['black_listed_ip']:
                blacklisted_ips.add(ip_dst)
                suspicious_ips.add(ip_src)
                source_dest_pairs.append((ip_src, ip_dst))

            if suspicious_ips:
                send_notification("Suspicious activity detected")
                for ip in suspicious_ips:
                    location_info = ipinfo_city(ip, config['api_keys']['ipinfo'])
                    if location_info:
                        print(f"[*] Suspicious IP: {ip}")
                        print(f"[*] Target: {location_info['ip']} Geo Located.")
                        print(f"[+] City: {location_info['city']}, Region: {location_info['region']}, Country: {location_info['country']}")
                        print(f"[+] Latitude: {location_info['latitude']}, Longitude: {location_info['longitude']}")
                    else:
                        print(f"No location information available for {ip}")

                print("\nSource IP --------> Destination IP")
                for src_ip, dst_ip in source_dest_pairs:
                    print(f"{src_ip} --------> {dst_ip}")

    # Print welcome message and stylish banner
    print(r'''
 | \ | |    | |                    | ||_   _|        / _|/ _(_)     / _ \            | |                   
|  \| | ___| |___      _____  _ __| | _| |_ __ __ _| |_| |_ _  ___/ /_\ \_ __   __ _| |_   _ _______ _ __ 
| . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ / | '__/ _` |  _|  _| |/ __|  _  | '_ \ / _` | | | | |_  / _ \ '__|
| |\  |  __/ |_ \ V  V / (_) | |  |   <| | | | (_| | | | | | | (__| | | | | | | (_| | | |_| |/ /  __/ |   
\_| \_/\___|\__| \_/\_/ \___/|_|  |_|\_\_/_|  \__,_|_| |_| |_|\___\_| |_/_| |_|\__,_|_|\__, /___\___|_|   
                                                                                        __/ |             
                                                                                       |___/     
''')

    print("Welcome to Network Traffic Analyzer")
    print("Checking for suspicious activity...\n")

    # Print message indicating analyzing traffic
    print("Analyzing traffic...")

    sniff(prn=packet_callback, store=0)

# Function to generate a report
def generate_report(config):
    global suspicious_ips, source_dest_pairs
    with open('report.txt', 'w') as file:
        file.write("Suspicious Activity Detected\n\n")
        for ip in suspicious_ips:
            location_info = ipinfo_city(ip, config['api_keys']['ipinfo'])
            if location_info:
                file.write(f"[*] Suspicious IP: {ip}\n")
                file.write(f"[*] Target: {location_info['ip']} Geo Located.\n")
                file.write(f"[+] City: {location_info['city']}, Region: {location_info['region']}, Country: {location_info['country']}\n")
                file.write(f"[+] Latitude: {location_info['latitude']}, Longitude: {location_info['longitude']}\n\n")
            else:
                file.write(f"No location information available for {ip}\n")

        file.write("\nSource IP --------> Destination IP\n")
        for src_ip, dst_ip in source_dest_pairs:
            file.write(f"{src_ip} --------> {dst_ip}\n")

# Entry point of the program
def main():
    # Load configuration from file
    config = load_config("config.yaml")

    # Call the function to perform analysis on the captured network traffic
    perform_analysis(config)

    # Generate a report
    generate_report(config)



if __name__ == "__main__":

    main()

