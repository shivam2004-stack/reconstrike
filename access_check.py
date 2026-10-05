"""
ReconStrike - Access Check Module (Step 2)
--------------------------------------------
Purpose: Reads scan_results.json (produced by scanner.py) and checks
discovered open ports/services for weak or default credentials.
 
Educational use only. Only run this against machines you own or have
explicit permission to test (e.g. your local Docker containers like
DVWA, Metasploitable, TryHackMe/HackTheBox targets).
"""
 
import json
import re
import requests
import ftplib
 
try:
    import paramiko
except ImportError:
    paramiko = None  # SSH check will be skipped if paramiko isn't installed
 
 
# A small, safe wordlist for demo/testing purposes only.
COMMON_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
]
 
 
def load_scan_results(filename="scan_results.json"):
    with open(filename, "r") as f:
        return json.load(f)
 
 
def check_http_login(target_ip, port):
    """
    Tries common default credentials against a DVWA-style login form.
    DVWA's login page is at /login.php and expects fields: username,
    password, Login.
    """
    url = f"http://{target_ip}:{port}/login.php"
    findings = []
 
    try:
        session = requests.Session()
 
        for username, password in COMMON_CREDENTIALS:
            # DVWA's login form includes a CSRF token (user_token) that
            # changes on every page load. We must fetch a fresh one and
            # send it along with each login attempt, or DVWA silently
            # rejects the request even with correct credentials.
            get_resp = session.get(url, timeout=5)
            if get_resp.status_code != 200:
                print(f"[!] Could not reach {url} (status {get_resp.status_code}) - skipping HTTP check.")
                return findings
 
            token_match = re.search(r"user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]", get_resp.text)
            user_token = token_match.group(1) if token_match else ""
 
            data = {
                "username": username,
                "password": password,
                "Login": "Login",
                "user_token": user_token,
            }
            login_resp = session.post(url, data=data, timeout=5)
 
            # --- DEBUG: remove once working ---
            print(f"    [debug] token found: {'yes - ' + user_token[:10] + '...' if user_token else 'NO TOKEN FOUND'}")
            print(f"    [debug] login_resp.url: {login_resp.url}")
            print(f"    [debug] status code: {login_resp.status_code}")
            if "incorrect" in login_resp.text.lower() or "login failed" in login_resp.text.lower():
                print(f"    [debug] page contains an error message")
            # --- END DEBUG ---
 
            # A weak signal: DVWA redirects to index.php on success
            if "index.php" in login_resp.url or "Logout" in login_resp.text:
                findings.append({
                    "port": port,
                    "service": "http",
                    "issue": "Weak/default login accepted",
                    "credentials": f"{username}:{password}"
                })
                print(f"  [VULNERABLE] {username}:{password} worked on {url}")
                break  # stop after first successful hit
        else:
            print(f"  [OK] No default credentials worked on {url}")
 
    except requests.exceptions.RequestException as e:
        print(f"[!] HTTP check failed for {url}: {e}")
 
    return findings
 
 
def check_ssh_login(target_ip, port):
    """Tries common credentials over SSH using paramiko."""
    findings = []
    if paramiko is None:
        print("[!] paramiko not installed - skipping SSH check. (pip install paramiko)")
        return findings
 
    for username, password in COMMON_CREDENTIALS:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(target_ip, port=port, username=username,
                            password=password, timeout=4, banner_timeout=4)
            findings.append({
                "port": port,
                "service": "ssh",
                "issue": "Weak/default login accepted",
                "credentials": f"{username}:{password}"
            })
            print(f"  [VULNERABLE] SSH {username}:{password} worked on port {port}")
            client.close()
            break
        except paramiko.AuthenticationException:
            continue
        except Exception as e:
            print(f"[!] SSH connection issue on port {port}: {e}")
            break
    else:
        print(f"  [OK] No default SSH credentials worked on port {port}")
 
    return findings
 
 
def check_ftp_login(target_ip, port):
    """Tries common credentials over FTP."""
    findings = []
    for username, password in COMMON_CREDENTIALS:
        try:
            ftp = ftplib.FTP()
            ftp.connect(target_ip, port, timeout=4)
            ftp.login(username, password)
            findings.append({
                "port": port,
                "service": "ftp",
                "issue": "Weak/default login accepted",
                "credentials": f"{username}:{password}"
            })
            print(f"  [VULNERABLE] FTP {username}:{password} worked on port {port}")
            ftp.quit()
            break
        except ftplib.error_perm:
            continue
        except Exception as e:
            print(f"[!] FTP connection issue on port {port}: {e}")
            break
    else:
        print(f"  [OK] No default FTP credentials worked on port {port}")
 
    return findings
 
 
def run_access_checks(scan_data):
    target_ip = scan_data["target"]
    all_findings = []
 
    for entry in scan_data["open_ports"]:
        port = entry["port"]
        service = entry["service"].lower()
 
        print(f"\n[*] Checking port {port} ({service}) ...")
 
        if service == "http":
            all_findings += check_http_login(target_ip, port)
        elif service == "ssh":
            all_findings += check_ssh_login(target_ip, port)
        elif service == "ftp":
            all_findings += check_ftp_login(target_ip, port)
        else:
            print(f"  [-] No access-check module for service '{service}' yet - skipping.")
 
    return all_findings
 
 
def save_findings(findings, filename="access_check_results.json"):
    with open(filename, "w") as f:
        json.dump(findings, f, indent=4)
    print(f"\n[+] Access-check results saved to {filename}")
 
 
if __name__ == "__main__":
    scan_data = load_scan_results()
    findings = run_access_checks(scan_data)
 
    print("\n=== Access Check Summary ===")
    if findings:
        for f in findings:
            print(f"  Port {f['port']} ({f['service']}): {f['issue']} -> {f['credentials']}")
    else:
        print("  No weak/default credentials found on any checked service.")
 
    save_findings(findings)
 


