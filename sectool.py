
import socket
import requests
import re
import hashlib
import ipaddress
from urllib.parse import urlparse


# -------------------- Banner --------------------

def banner():
    print("-" * 50)
    print("       SecTool Suite - Security Toolkit")
    print("-" * 50)


# -------------------- Port Scanner --------------------

def port_scanner():
    print("\n--- [1] Port Scanner ---")

    target = input("Enter target IP (e.g., 127.0.0.1): ").strip()

    try:
        ipaddress.ip_address(target)
    except ValueError:
        print("[-] Invalid IP address.")
        return

    ports = [21, 22, 80, 443, 3306, 8080]

    print(f"\n[*] Scanning {target}...")
    print("[*] Only scan systems you own or have permission to test.\n")

    for port in ports:
        try:
            with socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            ) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((target, port))

            if result == 0:
                print(f"[+] Port {port}: OPEN")
            else:
                print(f"[-] Port {port}: CLOSED or FILTERED")

        except OSError as error:
            print(f"[!] Port {port}: Error - {error}")


# -------------------- Directory Scanner --------------------

def dir_scanner():
    print("\n--- [2] Web Directory Scanner ---")

    target = input(
        "Enter authorized test URL (e.g., http://127.0.0.1:8000): "
    ).strip()

    parsed_url = urlparse(target)

    if (
        parsed_url.scheme not in ("http", "https")
        or not parsed_url.hostname
        or parsed_url.username
        or parsed_url.password
    ):
        print("[-] Invalid URL. Enter a valid HTTP or HTTPS URL.")
        return

    wordlist = [
        "admin",
        "login",
        "dashboard",
        "images",
        "config",
        "test",
    ]

    target = target.rstrip("/")

    print(f"\n[*] Scanning {target}...")
    print("[*] Use only on systems you are authorized to test.\n")

    try:
        for word in wordlist:
            url = f"{target}/{word}"

            try:
                response = requests.get(
                    url,
                    timeout=3,
                    allow_redirects=False,
                )

                status = response.status_code

                if status == 200:
                    print(f"[+] Found (200): {url}")
                elif status == 403:
                    print(f"[!] Forbidden (403): {url}")
                elif 300 <= status < 400:
                    print(f"[*] Redirect ({status}): {url}")
                elif status == 404:
                    print(f"[-] Not Found (404): {url}")
                elif status == 429:
                    print(f"[!] Rate limited (429): {url}")

            except requests.exceptions.Timeout:
                print(f"[!] Request timed out: {url}")

            except requests.exceptions.RequestException as error:
                print(f"[-] Request failed: {error}")
                break

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")


# -------------------- Log IP Extractor --------------------

def log_extractor():
    print("\n--- [3] Log IP Extractor ---")

    log_file = input(
        "Enter log file path (default: samples/sample.log): "
    ).strip()

    if not log_file:
        log_file = "samples/sample.log"

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    valid_ips = []
    invalid_ips = []

    try:
        with open(log_file, "r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                candidates = re.findall(ip_pattern, line)

                for candidate in candidates:
                    try:
                        ipaddress.IPv4Address(candidate)
                        valid_ips.append((candidate, line_number))

                    except ipaddress.AddressValueError:
                        invalid_ips.append((candidate, line_number))

        if valid_ips:
            print("\n[+] Valid IP addresses:")

            for ip, line_number in valid_ips:
                print(f" -> {ip} (line {line_number})")
        else:
            print("\n[-] No valid IPv4 addresses found.")

        if invalid_ips:
            print("\n[!] Invalid IP addresses ignored:")

            for ip, line_number in invalid_ips:
                print(f" -> {ip} (line {line_number})")

        print(f"\n[*] Valid IP occurrences: {len(valid_ips)}")
        print(f"[*] Invalid IP occurrences: {len(invalid_ips)}")

    except FileNotFoundError:
        print(f"[-] File not found: {log_file}")

    except UnicodeDecodeError:
        print("[-] Could not decode the file as UTF-8.")

    except OSError as error:
        print(f"[-] Could not read file: {error}")


# -------------------- SHA-256 Hash Generator --------------------

def hash_generator():
    print("\n--- [4] SHA-256 Hash Generator ---")

    text = input("Enter text to hash: ")

    hash_result = hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()

    print(f"\n[+] SHA-256 Hash: {hash_result}")


# -------------------- Main Menu --------------------

def main():
    while True:
        banner()

        print("1. Port Scanner")
        print("2. Web Directory Scanner")
        print("3. Log IP Extractor")
        print("4. SHA-256 Hash Generator")
        print("5. Exit")

        choice = input("\nSelect an option (1-5): ").strip()

        if choice == "1":
            port_scanner()

        elif choice == "2":
            dir_scanner()

        elif choice == "3":
            log_extractor()

        elif choice == "4":
            hash_generator()

        elif choice == "5":
            print("\nExiting SecTool Suite.")
            break

        else:
            print("\n[-] Invalid choice. Select a number from 1 to 5.")

        input("\nPress Enter to continue...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Program interrupted.")
