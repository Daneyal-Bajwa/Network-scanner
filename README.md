# Python Network & Vulnerability Scanner

A lightweight, concurrent network scanner built in Python that identifies active hosts, open ports, service banners, and checks them against the NIST National Vulnerability Database (NVD) for known CVEs. 

This project was developed to demonstrate core networking concepts, concurrent programming, and API integration.

## ⚠️ Ethical Disclaimer & Acceptable Use
**This tool is strictly for educational purposes and authorised testing only.** Scanning networks, ports, or services without explicit, written consent from the network owner is illegal and unethical. The developer assumes no liability and is not responsible for any misuse or damage caused by this program. Do not use this tool on any system or network you do not own or do not have permission to test.

## Features
* **Host Discovery:** Validates subnets and uses ICMP ping sweeps to identify active devices.
* **Concurrent Port Scanning:** Utilises `ThreadPoolExecutor` to rapidly scan common ports (e.g., 22, 80, 443) across multiple hosts simultaneously.
* **Service Banner Grabbing:** Extracts software versions from service headers (HTTP, SSH, etc.) via raw socket connections.
* **Automated CVE Lookups:** Integrates with the NIST NVD API to automatically flag known vulnerabilities (CVEs) and their CVSS severity scores based on grabbed banners.
* **JSON Reporting:** Automatically compiles and exports scan results into a readable `.json` file for further analysis.

## Prerequisites
* Python 3.x
* The `requests` library (for NVD API queries)

You can install the required dependency via pip:
`pip install requests`

## How to Run
Ensure you have permission to scan the target network.

Run the script from your terminal:
'python network_scanner.py'
OR
'streamlit run run-web.py'

## Technical Skills Demonstrated
* Network Socket Programming
* Asynchronous / Concurrent Execution
* REST API Integration & Rate-Limit Handling (NVD)
* Data Parsing & Error Handling
