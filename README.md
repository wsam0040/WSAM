
# WSAM - Web Security Analyzer Master

WSAM is an open-source tool designed for comprehensive web security testing. It helps detect common vulnerabilities in websites:

- SQL Injection
- XSS (Cross-Site Scripting)
- Command Injection
- Directory Traversal
- Open Redirect

It also provides various useful features such as:

- SSL certificate analysis
- HTTP header analysis
- Common port scanning
- Subdomain enumeration
- DNS lookup

## Usage

```bash
python3 wepv5.py
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
