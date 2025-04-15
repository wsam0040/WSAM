
# WSAM - Web Security Analyzer Master

**WSAM** is a powerful open-source tool for **advanced web security analysis**. It performs comprehensive security scans to detect common vulnerabilities and gather insightful information about web targets.

Whether you're a **penetration tester**, **bug bounty hunter**, or **cybersecurity enthusiast**, WSAM streamlines your reconnaissance and vulnerability discovery process.

---

## Features

WSAM includes a wide range of built-in modules to support in-depth analysis:

### Vulnerability Detection:
- **SQL Injection**
- **Cross-Site Scripting (XSS)**
- **Command Injection**
- **Directory Traversal**
- **Open Redirect**

### Information Gathering:
- **SSL Certificate Analysis**
- **HTTP Header Analysis**
- **Common Port Scanning**
- **Subdomain Enumeration**
- **DNS Lookup**

---

## Installation

Clone the tool using Git:

```bash
git clone https://github.com/wsam0040/wsam.git
cd wsam
pip install -r requirements.txt
```

---

## Usage

Run the tool with:

```bash
python3 wsam.py
```

You will be prompted to enter a target URL:

```bash
Enter Target URL (e.g., https://example.com):
```

The tool will begin analyzing the target and display real-time results.

---

## Export Results

After the scan completes, you will have the option to export all findings to a JSON file for later review or reporting.

---

## Requirements

- Python 3.8+
- requests
- dnspython
- termcolor

Install dependencies using:

```bash
pip install -r requirements.txt
```

---

## Legal Disclaimer

> This tool is intended for educational and authorized testing purposes only. Do not use WSAM against any target without explicit permission. Unauthorized use may violate local or international laws.

---

## Contributing

Feel free to fork the project and submit pull requests. Contributions are welcome!

---

## Author

Developed by @wsam0040  
Tool Name: Web Security Analyzer Master (WSAM)

---

## License

This project is licensed under the MIT License.
