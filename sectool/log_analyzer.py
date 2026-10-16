import ipaddress
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TIMESTAMP_PATTERN = re.compile(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]")
FAILED_PATTERN = re.compile(r"\bfailed\s+login\b", re.IGNORECASE)
SUCCESS_PATTERN = re.compile(r"\bsuccessful\s+login\b", re.IGNORECASE)


def analyze_log_file(file_path):
    """Extract valid and invalid IPv4 addresses and report their line numbers."""
    path = Path(file_path)
    valid_ips, invalid_ips = [], []
    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            for candidate in IP_PATTERN.findall(line):
                try:
                    ipaddress.IPv4Address(candidate)
                    valid_ips.append({"ip": candidate, "line": line_number})
                except ipaddress.AddressValueError:
                    invalid_ips.append({"ip": candidate, "line": line_number})
    return {
        "valid_ips": valid_ips,
        "invalid_ips": invalid_ips,
        "valid_count": len(valid_ips),
        "invalid_count": len(invalid_ips),
    }


def detect_brute_force(file_path, threshold=3, window_minutes=5):
    """
    Detect IPs with at least `threshold` failed logins within a rolling time window.
    Expected line format: [YYYY-MM-DD HH:MM:SS] Failed login from 10.0.0.5
    Lines without a valid timestamp, failed-login marker, and valid IPv4 are ignored.
    """
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")

    events = defaultdict(list)
    with Path(file_path).open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not FAILED_PATTERN.search(line):
                continue
            timestamp_match = TIMESTAMP_PATTERN.search(line)
            ip_match = IP_PATTERN.search(line)
            if not timestamp_match or not ip_match:
                continue
            try:
                timestamp = datetime.strptime(timestamp_match.group(1), "%Y-%m-%d %H:%M:%S")
                ip = str(ipaddress.IPv4Address(ip_match.group(0)))
            except (ValueError, ipaddress.AddressValueError):
                continue
            events[ip].append({"timestamp": timestamp, "line": line_number})

    alerts = []
    window = timedelta(minutes=window_minutes)
    for ip, records in events.items():
        records.sort(key=lambda item: item["timestamp"])
        left = 0
        for right, record in enumerate(records):
            while record["timestamp"] - records[left]["timestamp"] > window:
                left += 1
            count = right - left + 1
            if count >= threshold:
                alerts.append({
                    "ip": ip,
                    "failed_attempts": count,
                    "window_minutes": window_minutes,
                    "start": records[left]["timestamp"].isoformat(sep=" "),
                    "end": record["timestamp"].isoformat(sep=" "),
                    "lines": [item["line"] for item in records[left:right + 1]],
                    "alert": "Possible brute-force activity",
                })
                break

    alerts.sort(key=lambda item: item["ip"])
    total_failed = sum(len(items) for items in events.values())
    return {
        "threshold": threshold,
        "window_minutes": window_minutes,
        "total_failed_attempts": total_failed,
        "alerts": alerts,
        "alert_count": len(alerts),
    }
