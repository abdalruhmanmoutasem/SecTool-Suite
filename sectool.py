import argparse
import json
import sys

from sectool.dir_scanner import scan_directories
from sectool.hash_tools import sha256_file, sha256_text, verify_file_hash
from sectool.log_analyzer import analyze_log_file, detect_brute_force
from sectool.port_scanner import scan_ports
from sectool.reporting import save_json_report


def print_json(data):
    print(json.dumps(data, indent=2, ensure_ascii=False))


def run_menu():
    while True:
        print("\n========== SecTool Suite ==========")
        print("1. Port Scanner")
        print("2. Directory Scanner")
        print("3. Log Analyzer")
        print("4. SHA256 Text Hash")
        print("5. File Integrity Checker")
        print("0. Exit")
        choice = input("\nChoose an option: ").strip()
        try:
            if choice == "1":
                target = input("Target IPv4 (authorized target only): ").strip()
                raw_ports = input("Ports comma-separated [21,22,80,443,3306,8080]: ").strip()
                ports = [int(p.strip()) for p in raw_ports.split(",")] if raw_ports else [21, 22, 80, 443, 3306, 8080]
                timeout = float(input("Timeout seconds [1]: ").strip() or "1")
                print_json(scan_ports(target, ports, timeout))
            elif choice == "2":
                url = input("Base URL (authorized target only): ").strip()
                print_json(scan_directories(url))
            elif choice == "3":
                path = input("Log path [samples/sample.log]: ").strip() or "samples/sample.log"
                print_json(analyze_log_file(path))
                use_brute = input("Also detect brute-force attempts? (y/N): ").strip().lower()
                if use_brute == "y":
                    threshold = int(input("Failed attempts threshold [3]: ").strip() or "3")
                    window = int(input("Window minutes [5]: ").strip() or "5")
                    print_json(detect_brute_force(path, threshold, window))
            elif choice == "4":
                print("SHA256:", sha256_text(input("Text to hash: ")))
            elif choice == "5":
                path = input("File path: ").strip()
                expected = input("Expected SHA256 (leave blank to calculate only): ").strip()
                actual = sha256_file(path)
                print("SHA256:", actual)
                if expected:
                    print("Matches expected hash:", verify_file_hash(path, expected)["matches"])
            elif choice == "0":
                print("Goodbye!")
                return
            else:
                print("Invalid choice. Please choose 0-5.")
        except (ValueError, OSError) as exc:
            print(f"Error: {exc}")


def build_parser():
    parser = argparse.ArgumentParser(description="Small defensive security toolkit for authorized testing.")
    sub = parser.add_subparsers(dest="command")

    log_parser = sub.add_parser("log", help="Extract valid/invalid IPs from a log file")
    log_parser.add_argument("file", nargs="?", default="samples/sample.log")
    log_parser.add_argument("--json", dest="report", help="Save output to a JSON report")

    brute = sub.add_parser("bruteforce", help="Detect repeated failed logins in a time window")
    brute.add_argument("file", nargs="?", default="samples/bruteforce.log")
    brute.add_argument("--threshold", type=int, default=3)
    brute.add_argument("--window", type=int, default=5)
    brute.add_argument("--json", dest="report", help="Save output to a JSON report")

    ports = sub.add_parser("ports", help="Scan TCP ports on an authorized IPv4 target")
    ports.add_argument("target")
    ports.add_argument("--ports", default="21,22,80,443,3306,8080")
    ports.add_argument("--timeout", type=float, default=1.0)
    ports.add_argument("--json", dest="report", help="Save output to a JSON report")

    dirs = sub.add_parser("dirs", help="Check common paths on an authorized website")
    dirs.add_argument("url")
    dirs.add_argument("--timeout", type=float, default=5)
    dirs.add_argument("--json", dest="report", help="Save output to a JSON report")

    hash_parser = sub.add_parser("hash", help="Calculate SHA256 of text or a file")
    hash_parser.add_argument("value", help="Text to hash, or file path with --file")
    hash_parser.add_argument("--file", action="store_true", help="Treat value as a file path")

    verify = sub.add_parser("verify", help="Compare a file SHA256 against an expected hash")
    verify.add_argument("file")
    verify.add_argument("expected")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        run_menu()
        return 0
    try:
        if args.command == "log":
            result = analyze_log_file(args.file)
            print_json(result)
            if args.report:
                print(f"Report saved: {save_json_report(result, args.report)}")
        elif args.command == "bruteforce":
            result = detect_brute_force(args.file, args.threshold, args.window)
            print_json(result)
            if args.report:
                print(f"Report saved: {save_json_report(result, args.report)}")
        elif args.command == "ports":
            port_list = [int(part.strip()) for part in args.ports.split(",")]
            result = scan_ports(args.target, port_list, args.timeout)
            print_json(result)
            if args.report:
                print(f"Report saved: {save_json_report(result, args.report)}")
        elif args.command == "dirs":
            result = scan_directories(args.url, timeout=args.timeout)
            print_json(result)
            if args.report:
                print(f"Report saved: {save_json_report(result, args.report)}")
        elif args.command == "hash":
            print(sha256_file(args.value) if args.file else sha256_text(args.value))
        elif args.command == "verify":
            result = verify_file_hash(args.file, args.expected)
            print_json(result)
            return 0 if result["matches"] else 1
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
