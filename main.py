"""
ReconStrike - Main Pipeline
-----------------------------
Combines the scanning and access-check modules into a single,
one-command pentesting workflow:
 
    1. Scan the target for open ports/services
    2. Check those services for weak/default credentials
    3. Print and save a combined summary report
 
Usage:
    sudo venv/bin/python3 main.py --target 127.0.0.1
 
Educational use only. Only run this against machines you own or have
explicit permission to test (e.g. your local Docker containers like
DVWA, Metasploitable, TryHackMe/HackTheBox targets).
"""
 
import argparse
import json
from datetime import datetime
 
from scanner import scan_target, save_results, print_summary
from access_check import run_access_checks, save_findings
 
 
def run_pipeline(target_ip: str, port_range: str = "1-1024"):
    print(f"\n{'=' * 50}")
    print(f"  ReconStrike - Recon + Access-Check Pipeline")
    print(f"  Target: {target_ip}")
    print(f"{'=' * 50}\n")
 
    # --- Step 1: Scan ---
    print("[Phase 1] Scanning target for open ports...\n")
    scan_data = scan_target(target_ip, port_range)
    print_summary(scan_data)
    save_results(scan_data)
 
    if not scan_data["open_ports"]:
        print("\n[!] No open ports found - nothing to access-check. Stopping here.")
        return
 
    # --- Step 2: Access Check ---
    print("\n[Phase 2] Checking discovered services for weak credentials...")
    findings = run_access_checks(scan_data)
    save_findings(findings)
 
    # --- Combined Report ---
    report = {
        "target": target_ip,
        "scan_time": scan_data["scan_time"],
        "open_ports": scan_data["open_ports"],
        "vulnerabilities_found": findings,
    }
    report_filename = "reconstrike_report.json"
    with open(report_filename, "w") as f:
        json.dump(report, f, indent=4)
 
    print(f"\n{'=' * 50}")
    print("  FINAL REPORT")
    print(f"{'=' * 50}")
    print(f"  Target scanned: {target_ip}")
    print(f"  Open ports found: {len(scan_data['open_ports'])}")
    print(f"  Weak credentials found: {len(findings)}")
    if findings:
        for f_entry in findings:
            print(f"    -> Port {f_entry['port']} ({f_entry['service']}): {f_entry['credentials']}")
    print(f"\n[+] Full combined report saved to {report_filename}")
 
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ReconStrike - Automated recon + access-check pentesting tool"
    )
    parser.add_argument(
        "--target", required=True, help="Target IP address to scan (e.g. 127.0.0.1)"
    )
    parser.add_argument(
        "--ports", default="1-1024", help="Port range to scan (default: 1-1024)"
    )
    args = parser.parse_args()
 
    run_pipeline(args.target, args.ports)
 
