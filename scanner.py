"""
ReconStrike - Scanner Module (Step 1)
--------------------------------------
Purpose: Scan a target IP for open ports and identify running services.
This is the "recon" half of ReconStrike. Output feeds into the
access-check module in the next step.

⚠️ Educational use only. Only scan machines you own or have explicit
permission to test (e.g. your local Docker containers, Metasploitable,
TryHackMe/HackTheBox targets).
"""

import nmap
import json
from datetime import datetime


def scan_target(target_ip: str, port_range: str = "1-1024") -> dict:
    """
    Scans the given target IP for open ports and their services.

    Args:
        target_ip: IP address to scan (e.g. "127.0.0.1")
        port_range: Port range to scan (default covers common ports)

    Returns:
        A dictionary with scan results, structured like:
        {
            "target": "127.0.0.1",
            "scan_time": "2026-09-24 12:00:00",
            "open_ports": [
                {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "8.9"},
                {"port": 80, "service": "http", "product": "Apache", "version": "2.4"}
            ]
        }
    """
    scanner = nmap.PortScanner()

    print(f"[*] Scanning {target_ip} on ports {port_range} ... this may take a moment.")
    scanner.scan(target_ip, port_range, arguments="-sV")  # -sV = detect service/version

    results = {
        "target": target_ip,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "open_ports": []
    }

    # nmap-python stores results per host; we only scan one host at a time
    if target_ip not in scanner.all_hosts():
        print("[!] No response from target. Is it online and reachable?")
        return results

    for proto in scanner[target_ip].all_protocols():  # usually just "tcp"
        ports = scanner[target_ip][proto].keys()
        for port in sorted(ports):
            port_info = scanner[target_ip][proto][port]
            if port_info["state"] == "open":
                results["open_ports"].append({
                    "port": port,
                    "service": port_info.get("name", "unknown"),
                    "product": port_info.get("product", ""),
                    "version": port_info.get("version", "")
                })

    return results


def save_results(results: dict, filename: str = "scan_results.json"):
    """Saves scan results to a JSON file so the next module can read it."""
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)
    print(f"[+] Results saved to {filename}")


def print_summary(results: dict):
    """Prints a human-readable summary of the scan to the terminal."""
    print(f"\n=== Scan Summary for {results['target']} ===")
    if not results["open_ports"]:
        print("No open ports found.")
        return

    for entry in results["open_ports"]:
        service_info = entry["service"]
        if entry["product"]:
            service_info += f" ({entry['product']} {entry['version']})"
        print(f"  Port {entry['port']:<6} -> {service_info}")


if __name__ == "__main__":
    # --- Quick test run ---
    # Change this to your Docker container's mapped IP/port range if needed
    TARGET = "127.0.0.1"

    scan_results = scan_target(TARGET)
    print_summary(scan_results)
    save_results(scan_results)


