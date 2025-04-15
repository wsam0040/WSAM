import requests, socket, ssl, random, threading, re, time, dns.resolver, subprocess, platform
from urllib.parse import urlparse
from termcolor import colored
import ipaddress
import os
from requests.exceptions import RequestException
import json

# ----------------------- Banner -----------------------
def banner():
    print(colored("""
██     ██ ███████ ███████  █████  ███    ███ 
██     ██ ██      ██      ██   ██ ████  ████ 
██  █  ██ █████   █████   ███████ ██ ████ ██ 
██ ███ ██ ██      ██      ██   ██ ██  ██  ██ 
 ███ ███  ███████ ███████ ██   ██ ██      ██   v20
        Web Security Analyzer Master
""", "cyan"))

# ----------------------- Config -----------------------
HEADERS = {
    'User-Agent': random.choice([
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Mozilla/5.0 (X11; Linux x86_64)',
        'curl/7.68.0',
        'WSAM-Scanner/20.0'
    ])
}
TIMEOUT = 10
SUBDOMAINS = ['admin', 'test', 'mail', 'dev', 'beta', 'cpanel', 'api', 'portal']
PORTS = [80, 443, 21, 22, 8080, 8443, 3306]

# ----------------------- Results Storage -----------------------
results = {
    "dns_lookup": [],
    "ssl_info": {},
    "http_headers": [],
    "ports": [],
    "subdomains": [],
    "sqli_vulnerabilities": [],
    "xss_vulnerabilities": [],
    "cmd_injection_vulnerabilities": [],
    "dir_traversal_vulnerabilities": [],
    "open_redirect_vulnerabilities": [],
}

# ----------------------- Utils -----------------------
def print_result(message, color):
    print(colored(message, color))

# ----------------------- DNS Lookup -----------------------
def dns_lookup(domain):
    print_result("[*] Performing DNS Lookup...", "yellow")
    try:
        result = dns.resolver.resolve(domain, 'A')
        for ipval in result:
            results["dns_lookup"].append(f"DNS IP: {ipval.to_text()}")
            print_result(f"    [+] DNS IP: {ipval.to_text()}", "green")
    except dns.resolver.NoAnswer:
        results["dns_lookup"].append(f"No DNS records found for {domain}")
        print_result(f"    [-] No DNS records found for {domain}", "red")
    except Exception as e:
        results["dns_lookup"].append(f"Error in DNS lookup: {str(e)}")
        print_result(f"    [-] Error in DNS lookup: {str(e)}", "red")

# ----------------------- SSL & HTTP Analysis -----------------------
def check_ssl_info(domain):
    print_result("[*] Checking SSL Certificate...", "yellow")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                results["ssl_info"]["issuer"] = cert['issuer'][0][0][1]
                results["ssl_info"]["valid_from"] = cert['notBefore']
                results["ssl_info"]["valid_until"] = cert['notAfter']
                print_result(f"    [+] SSL Issuer: {cert['issuer'][0][0][1]}", "green")
                print_result(f"    [+] SSL Valid From: {cert['notBefore']}", "green")
                print_result(f"    [+] SSL Valid Until: {cert['notAfter']}", "green")
    except:
        results["ssl_info"]["error"] = "SSL Certificate not found."
        print_result("    [-] SSL Certificate not found.", "red")

def analyze_headers(url):
    print_result("[*] Analyzing HTTP Headers...", "yellow")
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        for k, v in r.headers.items():
            results["http_headers"].append(f"{k}: {v}")
            print_result(f"    [+] Header: {k}: {v}", "blue")
    except:
        results["http_headers"].append("Failed to retrieve HTTP headers.")
        print_result("    [-] Failed to retrieve HTTP headers.", "red")

# ----------------------- Port Scanning -----------------------
def scan_ports(domain):
    print_result("[*] Scanning Common Ports...", "yellow")
    open_ports = []
    for port in PORTS:
        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect((domain, port))
            open_ports.append(port)
            sock.close()
            results["ports"].append(f"Port {port} is OPEN")
            print_result(f"    [+] Port {port} is OPEN", "green")
        except:
            continue
    if open_ports:
        print_result(f"    [+] Open Ports: {', '.join(map(str, open_ports))}", "green")
    else:
        results["ports"].append("No open ports found.")
        print_result("    [-] No open ports found.", "red")

# ----------------------- Subdomain Enumeration -----------------------
def subdomain_enum(domain):
    print_result("[*] Subdomain Enumeration...", "yellow")
    for sub in SUBDOMAINS:
        try:
            full = f"{sub}.{domain}"
            ip = socket.gethostbyname(full)
            results["subdomains"].append(f"Subdomain Found: {full} -> {ip}")
            print_result(f"    [+] Subdomain Found: {full} -> {ip}", "green")
        except:
            continue

# ----------------------- SQLi Detection -----------------------
def detect_sqli(url):
    print_result("[*] Testing for SQL Injection...", "yellow")
    payloads = [
        "' OR 1=1 --", "' OR 'a'='a", "' UNION SELECT NULL, NULL --", "1' AND 1=1 --"
    ]
    for payload in payloads:
        try:
            r = requests.get(url, params={"q": payload}, headers=HEADERS, timeout=TIMEOUT)
            if "error" in r.text.lower() or "mysql" in r.text.lower():
                results["sqli_vulnerabilities"].append(f"SQL Injection vulnerability detected with payload: {payload}")
                print_result(f"    [+] SQL Injection vulnerability detected with payload: {payload}", "red")
            else:
                results["sqli_vulnerabilities"].append(f"No SQLi vulnerability detected for payload: {payload}")
                print_result(f"    [+] No SQLi vulnerability detected for payload: {payload}", "green")
        except:
            continue

# ----------------------- XSS Detection -----------------------
def detect_xss(url):
    print_result("[*] Testing for Cross-site Scripting (XSS)...", "yellow")
    payloads = [
        "<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>", "<body onload=alert(1)>"
    ]
    for payload in payloads:
        try:
            r = requests.get(url, params={"q": payload}, headers=HEADERS, timeout=TIMEOUT)
            if payload in r.text:
                results["xss_vulnerabilities"].append(f"XSS vulnerability detected with payload: {payload}")
                print_result(f"    [+] XSS vulnerability detected with payload: {payload}", "red")
            else:
                results["xss_vulnerabilities"].append(f"No XSS vulnerability detected for payload: {payload}")
                print_result(f"    [+] No XSS vulnerability detected for payload: {payload}", "green")
        except:
            continue

# ----------------------- Command Injection -----------------------
def detect_cmd_injection(url):
    print_result("[*] Testing for Command Injection...", "yellow")
    payloads = [
        "; ls", "| ls", "&& whoami", "; id", "| id", "&& uname -a"
    ]
    for payload in payloads:
        try:
            r = requests.get(url, params={"q": payload}, headers=HEADERS, timeout=TIMEOUT)
            if "root" in r.text or "id" in r.text:
                results["cmd_injection_vulnerabilities"].append(f"Command Injection vulnerability detected with payload: {payload}")
                print_result(f"    [+] Command Injection vulnerability detected with payload: {payload}", "red")
            else:
                results["cmd_injection_vulnerabilities"].append(f"No Command Injection vulnerability detected for payload: {payload}")
                print_result(f"    [+] No Command Injection vulnerability detected for payload: {payload}", "green")
        except:
            continue

# ----------------------- Directory Traversal -----------------------
def detect_dir_traversal(url):
    print_result("[*] Testing for Directory Traversal...", "yellow")
    payloads = [
        "../../etc/passwd", "../../../etc/passwd", "..%2f..%2fetc%2fpasswd"
    ]
    for payload in payloads:
        try:
            r = requests.get(url, params={"q": payload}, headers=HEADERS, timeout=TIMEOUT)
            if "root" in r.text or "bin" in r.text:
                results["dir_traversal_vulnerabilities"].append(f"Directory Traversal vulnerability detected with payload: {payload}")
                print_result(f"    [+] Directory Traversal vulnerability detected with payload: {payload}", "red")
            else:
                results["dir_traversal_vulnerabilities"].append(f"No Directory Traversal vulnerability detected for payload: {payload}")
                print_result(f"    [+] No Directory Traversal vulnerability detected for payload: {payload}", "green")
        except:
            continue

# ----------------------- Open Redirect -----------------------
def detect_open_redirect(url):
    print_result("[*] Testing for Open Redirect...", "yellow")
    payloads = [
        "http://evil.com", "https://malicious-site.com"
    ]
    for payload in payloads:
        try:
            r = requests.get(url, params={"redirect": payload}, headers=HEADERS, timeout=TIMEOUT)
            if payload in r.url:
                results["open_redirect_vulnerabilities"].append(f"Open Redirect vulnerability detected with payload: {payload}")
                print_result(f"    [+] Open Redirect vulnerability detected with payload: {payload}", "red")
            else:
                results["open_redirect_vulnerabilities"].append(f"No Open Redirect vulnerability detected for payload: {payload}")
                print_result(f"    [+] No Open Redirect vulnerability detected for payload: {payload}", "green")
        except Exception as e:
            print_result(f"    [-] Error while testing Open Redirect: {str(e)}", "red")
            continue

# ----------------------- Scan All -----------------------
def run_scan(url):
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path

    print_result(f"\n[*] Starting Scan on {domain}...\n", "cyan")
    
    # Run all tasks concurrently for faster results
    threads = [
        threading.Thread(target=dns_lookup, args=(domain,)),
        threading.Thread(target=check_ssl_info, args=(domain,)),
        threading.Thread(target=analyze_headers, args=(url,)),
        threading.Thread(target=scan_ports, args=(domain,)),
        threading.Thread(target=detect_sqli, args=(url,)),
        threading.Thread(target=detect_xss, args=(url,)),
        threading.Thread(target=detect_cmd_injection, args=(url,)),
        threading.Thread(target=subdomain_enum, args=(domain,)),
        threading.Thread(target=detect_dir_traversal, args=(url,)),
        threading.Thread(target=detect_open_redirect, args=(url,))  # Added the Open Redirect function here
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print_result("\n[*] Scan completed successfully.\n", "green")

    # Show Results
    display_results()

    # Option to export results to a JSON file
    export_option = input("Would you like to export results to a JSON file? (y/n): ").strip().lower()
    if export_option == 'y':
        export_results()

# ----------------------- Display Results -----------------------
def display_results():
    print_result("\n--- Scan Results ---", "cyan")
    
    # DNS Lookup Results
    print_result("\n[DNS Lookup Results]", "yellow")
    for item in results["dns_lookup"]:
        print_result(f"  {item}", "green")

    # SSL Information
    print_result("\n[SSL Certificate Information]", "yellow")
    if "error" in results["ssl_info"]:
        print_result(f"  {results['ssl_info']['error']}", "red")
    else:
        print_result(f"  Issuer: {results['ssl_info']['issuer']}", "green")
        print_result(f"  Valid From: {results['ssl_info']['valid_from']}", "green")
        print_result(f"  Valid Until: {results['ssl_info']['valid_until']}", "green")

    # HTTP Headers
    print_result("\n[HTTP Headers]", "yellow")
    for header in results["http_headers"]:
        print_result(f"  {header}", "blue")

    # Open Ports
    print_result("\n[Open Ports]", "yellow")
    for port in results["ports"]:
        print_result(f"  {port}", "green")

    # Subdomains
    print_result("\n[Subdomains]", "yellow")
    for subdomain in results["subdomains"]:
        print_result(f"  {subdomain}", "green")

    # Vulnerabilities
    print_result("\n[Vulnerabilities]", "yellow")

    # SQL Injection Vulnerabilities
    if results["sqli_vulnerabilities"]:
        print_result("\n  SQL Injection Vulnerabilities:", "red")
        for vuln in results["sqli_vulnerabilities"]:
            print_result(f"  {vuln}", "red")

    # XSS Vulnerabilities
    if results["xss_vulnerabilities"]:
        print_result("\n  Cross-site Scripting (XSS) Vulnerabilities:", "red")
        for vuln in results["xss_vulnerabilities"]:
            print_result(f"  {vuln}", "red")

    # Command Injection Vulnerabilities
    if results["cmd_injection_vulnerabilities"]:
        print_result("\n  Command Injection Vulnerabilities:", "red")
        for vuln in results["cmd_injection_vulnerabilities"]:
            print_result(f"  {vuln}", "red")

    # Directory Traversal Vulnerabilities
    if results["dir_traversal_vulnerabilities"]:
        print_result("\n  Directory Traversal Vulnerabilities:", "red")
        for vuln in results["dir_traversal_vulnerabilities"]:
            print_result(f"  {vuln}", "red")

    # Open Redirect Vulnerabilities
    if results["open_redirect_vulnerabilities"]:
        print_result("\n  Open Redirect Vulnerabilities:", "red")
        for vuln in results["open_redirect_vulnerabilities"]:
            print_result(f"  {vuln}", "red")

# ----------------------- Export Results to JSON -----------------------
def export_results():
    filename = input("Enter filename to save the results (e.g., 'scan_results.json'): ").strip()
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        print_result(f"Results successfully exported to {filename}.", "green")
    except Exception as e:
        print_result(f"Failed to export results: {str(e)}", "red")

# ----------------------- Main -----------------------
if __name__ == "__main__":
    banner()
    target = input("Enter Target URL (e.g., https://example.com): ").strip()
    if not target.startswith("http"):
        target = "http://" + target
    run_scan(target)