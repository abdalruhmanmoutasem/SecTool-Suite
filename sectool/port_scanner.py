import ipaddress
import socket


def scan_ports(target, ports, timeout=1.0):
    """Scan TCP ports on a valid IP address; use only on authorized targets."""
    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError("Target must be a valid IP address.") from exc
    if address.version != 4:
        raise ValueError("This scanner currently supports IPv4 targets only.")
    if not 0 < timeout <= 10:
        raise ValueError("Timeout must be between 0 and 10 seconds.")
    results = []
    for port in ports:
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(f"Invalid TCP port: {port}")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                status = "open" if sock.connect_ex((str(address), port)) == 0 else "closed_or_filtered"
        except OSError as exc:
            status = f"error: {exc}"
        results.append({"port": port, "status": status})
    return {"target": str(address), "results": results}
