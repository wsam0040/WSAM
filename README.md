# WSAM - Web Security Analyzer Master

**WSAM** is an advanced open-source tool for comprehensive web security testing. It is designed to detect and analyze a wide range of common vulnerabilities that could affect websites, helping security professionals and enthusiasts identify weaknesses and secure their web applications.

WSAM provides real-time feedback on critical security flaws and detailed insights into various aspects of the web target.

---

## Key Features

### Vulnerability Detection:
- **SQL Injection**: Identify SQL injection vulnerabilities in your web application's input fields.
- **Cross-Site Scripting (XSS)**: Detect reflected, stored, and DOM-based XSS vulnerabilities.
- **Command Injection**: Evaluate the potential for executing arbitrary system commands through user input.
- **Directory Traversal**: Identify if an attacker can access files outside the web root directory.
- **Open Redirect**: Detect open redirect vulnerabilities that allow attackers to redirect users to malicious websites.

### Information Gathering:
- **SSL Certificate Analysis**: Examine the SSL/TLS certificate of the target site for issues like expiration, weak ciphers, or missing validation.
- **HTTP Header Analysis**: Analyze HTTP headers to identify potential misconfigurations or missing security headers.
- **Common Port Scanning**: Scan for open ports commonly used by web applications (e.g., HTTP, HTTPS, FTP, SSH).
- **Subdomain Enumeration**: Identify subdomains associated with the target, which could expose additional vulnerabilities.
- **DNS Lookup**: Perform DNS lookups to gather details about the domain and its associated IP addresses.

---

## Installation

Clone the tool from GitHub and install the required dependencies:

```bash
git clone https://github.com/wsam0040/wsam.git
cd wsam
pip install -r requirements.txt

## Usage

```bash
python3 wsam.py
```

Simply enter the target URL when prompted.

## Requirements

- Python 3.8+
- dnspython
- requests
- termcolor

## Installation

```bash
pip install -r requirements.txt
```

## Export Results

After the scan is complete, you can save the results to a JSON file.

## Legal Disclaimer

This tool is developed for educational purposes only. It should not be used against any target without explicit permission.
