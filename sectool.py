import socket
import requests
import re
import hashlib
from datetime import datetime

def banner():
    print("-" * 50)
    print("       🛡️  SecTool Suite - All-in-One Security Tool  🛡️")
    print("-" * 50)

def port_scanner():
    print("\n--- [1] Port Scanner ---")
    target = input("Enter target IP (e.g., 127.0.0.1): ")
    ports = [21, 22, 80, 443, 3306, 8080]
    
    print(f"[*] Scanning {target}...")
    try:
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((target, port))
            if result == 0:
                print(f"[+] Port {port} is OPEN")
            s.close()
    except Exception as e:
        print(f"[-] Error: {e}")

def dir_scanner():
    print("\n--- [2] Web Directory Brute-Forcer ---")
    target = input("Enter target URL (e.g., http://example.com): ")
    wordlist = ["admin", "login", "dashboard", "images", "config", "test"]
    
    print(f"[*] Scanning directories on {target}...")
    for word in wordlist:
        url = f"{target}/{word}"
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                print(f"[+] Found (200): {url}")
            elif response.status_code == 403:
                print(f"[!] Forbidden (403): {url}")
        except requests.exceptions.ConnectionError:
            print("[-] Connection failed to target.")
            break

def log_extractor():
    print("\n--- [3] Log IP Extractor ---")
    log_sample = """
    [INFO] Connected from 192.168.1.10
    [WARNING] Failed login from 10.0.0.5
    [ERROR] Attack detected from 172.16.0.25
    """
    print("[*] Analyzing sample log data...")
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    found_ips = re.findall(ip_pattern, log_sample)
    
    print("[+] Extracted IPs:")
    for ip in found_ips:
        print(f" -> {ip}")

def hash_generator():
    print("\n--- [4] SHA-256 Hash Generator ---")
    text = input("Enter text to hash: ")
    hash_result = hashlib.sha256(text.encode()).hexdigest()
    print(f"[+] SHA-256 Hash: {hash_result}")

def main():
    while True:
        banner()
        print("1. Port Scanner")
        print("2. Web Directory Scanner")
        print("3. Log IP Extractor")
        print("4. Hash Generator")
        print("5. Exit")
        
        choice = input("\nSelect an option (1-5): ")
        
        if choice == '1':
            port_scanner()
        elif choice == '2':
            dir_scanner()
        elif choice == '3':
            log_extractor()
        elif choice == '4':
            hash_generator()
        elif choice == '5':
            print("\n[!] Exiting tool. Stay safe!")
            break
        else:
            print("\n[-] Invalid choice, please choose between 1 and 5.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()