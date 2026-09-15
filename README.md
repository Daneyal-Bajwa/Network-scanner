# Containerised Network & Vulnerability Scanner

A lightweight, concurrent network scanner built in Python that identifies active hosts, open ports, service banners, and checks them against the NIST National Vulnerability Database (NVD) for known CVEs. 

Originally developed as a standalone script, this project has been upgraded into a fully cloud-native DevSecOps pipeline. It features Docker containerisation, automated Kubernetes orchestration via CronJobs, and data persistence using MongoDB.

## ⚠️ Ethical Disclaimer & Acceptable Use
**This tool is strictly for educational purposes and authorised testing only.** Scanning networks, ports, or services without explicit, written consent from the network owner is illegal and unethical. The developer assumes no liability and is not responsible for any misuse or damage caused by this program. Do not use this tool on any system or network you do not own or do not have permission to test.

## Core Features
* **Host Discovery:** Validates subnets and uses ICMP ping sweeps to identify active devices.
* **Concurrent Port Scanning:** Utilises `ThreadPoolExecutor` to rapidly scan common ports (e.g., 22, 80, 443) across multiple hosts simultaneously.
* **Service Banner Grabbing:** Extracts software versions from service headers (HTTP, SSH, etc.) via raw socket connections.
* **Automated CVE Lookups:** Integrates with the NIST NVD API to automatically flag known vulnerabilities (CVEs) and their CVSS severity scores based on grabbed banners.
* **Kubernetes Orchestration:** Deployed as a K8s `CronJob` for automated nightly network monitoring, with `Job` manifest for ad-hoc incident response scanning.
* **Data Persistence:** Automatically injects scan results into an internal Kubernetes MongoDB pod for historical tracking and analysis.
* **Dynamic Network Detection:** Configured with K8s `hostNetwork` to dynamically detect and scan the local physical subnet.

## Architecture
* **Container Runtime:** The python scanner is packaged into a lightweight Docker image.
* **Database Layer:** A MongoDB Pod and Service run inside the cluster to store historical scan data.
* **Orchestration:** Kubernetes handles the scheduling, injecting environment variables (like Database URIs), and spinning up the scanner pods.

## Prerequisites
* Docker Desktop (with Kubernetes enabled in settings)
* kubectl (Kubernetes command-line tool)
* uv (for lightning-fast local python environment management)

## Local Development (Testing Method)
If you wish to test the scanner locally on your machine without spinning up the Kubernetes cluster, use `uv` to manage the isolated environment.

**1. Set up the environment and dependencies**

      uv venv
      uv pip install -r requirements.txt

Ensure you have permission to scan the target network.

**2. Run the CLI Scanner**

      python scanner.py


## Deployment: Kubernetes (Production Method)

**1. Build the Docker Image**

Package the local python code into a container image.

      docker build -t vuln-scanner:v1

**2. Deploy the Database**

Spin up the MongoDB instance inside the cluster.

      kubectl apply -f mongo-deployment.yaml
      kubectl apply -f mongo-service.yaml

**3. Configure and Schedule the Scanner**

Apply the environment variables and the CronJob to automate the nightly scans.

      kubectl apply -f scanner-config.yaml
      kubectl apply -f scanner-cronjob.yaml

(To trigger an ad-hoc scan immediately, run:

      kubectl create job --from=cronjob/nightly-network-scan manual-scan-01

## Technical Skills Demonstrated
* DevDecOps & Cloud-Native Architecture: Moving local scripts into containerised, scalable cloud environments.
* Containerisation: Dockerfile creation and image optimisation
* Kubernetes Orchestration: Deploying Pods, Services, ConfigMaps, Jobs, and CronJobs.
* Database Management: MongoDB deployment and python intergration (`pymongo`).
* Network Socket Programming & Concurrency: ThreadPoolExecutor and asynchronous execution.
* REST API Integration: Rate-limit handling and JSON data parsing (NIST NVD)
* Version Control: Git history management and conflict resolution.


