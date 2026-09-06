import socket
import concurrent.futures 
import subprocess
import json
import os
import requests
import time
import ipaddress
import platform
import pymongo
from datetime import datetime

ports = [22, 80, 443, 139, 445, 631, 3389, 8080, 8443]

# find the exact folder where this python script lives
script_dir = os.path.dirname(os.path.abspath(__file__))
# combine that folder with the file name
output_file = os.path.join(script_dir, "Reports\\network_scan.json")

SERVICES = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL"
}

def Get_Local_Subnet():
    # Get the current IP of the machine/container
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    # Automatically mask the IP to the base /24 subnet (e.g., 192.168.1.45 becomes 192.168.1.0/24)
    network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
    return str(network)

def Ping_Ip(ip: str) -> str | None:
    """
    Ping an IP to confirm whether it is active.
    
    Args:
        ip (str): The IP to be pinged.
        
    Returns:
        str: The IP is returned if it is active, otherwise None is returned.
    """
    # Run the Windows ping command silently 
    # subprocess.run pretends to be human typing in terminala dn connects to io pipes
    # -n 1 send only 1 network packet (default on windows is 4)
    # -w 500 wait time to 500ms
    # '-n' and '-w' for Windows, '-c' and '-W' for Linux/Mac
    if platform.system().lower() == "windows":
        command = ["ping", "-n", "1", "-w", "500", ip]
    else:
        command = ["ping", "-c", "1", "-W", "1", ip]
    result = subprocess.run(command, stdout=subprocess.DEVNULL)
    
    # Return code 0 means the device replied
    if result.returncode == 0:
        return ip
    
    return None

def Validate_Ip(subnet: str) -> bool:
    """
    Confirms whether a provided IP or subnet is valid or not.
    
    Args:
        subnet (str): The subnet or IP to be validated.
        
    Returns:
        bool: Returns if the provided subnet or IP is valid.
    """
    try:
        # use ipaddress library to validate subnet
        ipaddress.IPv4Network(subnet)
        return True
    except ValueError as e:
        print(f"Caught bad subnet: {e}")
        return False
    
def Get_Subnet(subnet: str) -> int:
    """
    Gets the amount of network address dedicated bits, provided a subnet
    
    Args:
        subnet (str): The subnet of the network in form such as 192.168.0.0/24 (must have 0 before /).
        
    Returns:
        int: The number of network address dedicated bits.
    """
    try:
        # provided something like "192.168.0.0/24", take the bit after the /
        a = int(subnet.split('/')[1])
        # if the network address is logically sound
        if (0 <= a <= 32):
            return a
    except:
        return -1
    return -1

def Generate_Ips(subnet: str) -> list[str]:
    """
    Generates a list of valid IPs given a subnet, using the ipaddress library in python.
    
    Args:
        subnet (str): The subnet of the network in form such as 192.168.0.0/24 (must have 0 before /). Can also just be an IP e.g. 192.168.0.1.
        
    Returns:
        list (str): A list of IPs consistent with the provided subnet.
    """
    # assumes subnet given has already been validated
    subnet_mask = Get_Subnet(subnet)
    # if no subnet mask is provided i.e. no /24 etc or /32, it means just one IP
    if subnet_mask == (-1 or 32):
        return [subnet]

    # works for /0 to /32 and generates list of ips
    network = ipaddress.IPv4Network(subnet, strict=False)

    return [str(ip) for ip in network.hosts()]

def Scan_Network(subnet: str) -> list[str]:
    """
    Scans a network for active hosts, or scans a target host for active ports.
    
    Args:
        subnet (str): The subnet of the network in form such as 192.168.0.0/24 (must have 0 before /). Can also just be an IP e.g. 192.168.0.1.
        
    Returns:
        list (str): A list of active hosts or active ports, depending on the provided subnet variable.
    """
    if not Validate_Ip(subnet):
        return    
    
    # Create a list of all IPs in the 
    ips = Generate_Ips(subnet)

    active = []

    print(f"Scanning...")

    # if only one ip is provided, scan it for ports, otherwise scan network for active ip
    if len(ips) == 1:
        active = Scan_Ip_Ports(ips[0])
    else:
        # Ping 50 IP addresses at the exact same time
        with concurrent.futures.ThreadPoolExecutor(max_workers=256) as executor:
            results = executor.map(Ping_Ip, ips)

            for value in results:
                if value is not None:
                    active.append(value)

    print("Scan complete.")
    return active

def Scan_Port(ip: str, port: int) -> tuple[str, bool]:
    """
    Scans for a specific port on the target IP by trying to connect to it.
    
    Args:
        ip (str): The target IP.
        port (int): The target port.
        
    Returns:
        tuple (str, bool): A tuple containing the port and vulnerability information, along with whether it is open or not.
    """
    try:
        # 'with' handles unexpected exceptions during 'connect_ex' so avoids crashing
        # socket.AF_INET is for IPV4
        # .SOCK_STREAM is for TCP 
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            # initiate a TCP handshake (SYN -> SYN-ACK -> ACK)
            result = sock.connect_ex((ip, port))

            # Web servers (80, 443, 8080) wait for us to speak first.
            # send a basic HTTP GET request to force them to reply
            # TODO: 443 and 8443 are secure http, need ssl wrapper
            if port in [80, 443, 8080, 8443]:
                request = f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
                sock.sendall(request.encode('utf-8'))

            # receive up to 1024 bytes of the server's response
            banner_bytes = sock.recv(1024)
            
            # decode the bytes to text, ignoring characters that can't be decoded
            banner = banner_bytes.decode('utf-8', errors='ignore').strip()

            if result == 0:
                # banners can be huge, just want the first line (up to 50 characters)
                if banner:
                    first_line = banner.split('\n')[0]
                    version = first_line.split(' ')[0]
                    result = Check_Vulnerabilities(version)
                    print(version)
                    print(result)
                    if result == []:
                        return f"Port {port} {first_line[:50].strip()}",True
                    else:
                        # getting just first one as there could be several
                        first_vuln = result[0]
                        return f"Port {port} {first_line[:50].strip()} !!! {first_vuln['cve_id']} (Severity: {first_vuln['score']})", True
                return f"Port {port}", False
            else:
                return port, False
    except (socket.timeout, TimeoutError):
        # banner request timed out
        return f"Port {port}", True
        
def Scan_Ip_Ports(ip: str, target_ports: list[int] = None) -> list[str] | None:
    """
    Scans the provided IP for the list of provided ports.
    
    Args:
        ip (str): The target IP.
        target_ports (list[int]): List of target ports.
        
    Returns:
        list[str]: A list of active ports found on the target IP, or an empty list if none found.
    """
    # if no target ports are provided, use default list
    if target_ports is None:
        target_ports = ports
    
    open_ports = []
    # using ThreadPoolExecutor to run scans concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        # map the target IP and ports to the scanning function
        futures = [executor.submit(Scan_Port, ip, port) for port in ports]
        
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            # if port is open, add it to the list
            if is_open:
                open_ports.append(port)
    # if list isn't empty, sort it
    if open_ports:
        open_ports.sort()
        return open_ports
    
    return None

def Check_Vulnerabilities(banner: str, max_retries: int = 2) -> list[dict]:
    """
    Queries the NIST NVD API for known vulnerabilities related to a service banner.
    
    Args:
        banner (str): The raw service banner (e.g., "Apache/2.4.41" or "OpenSSH 8.2").
        
    Returns:
        list[dict]: A list of dictionaries containing CVE details, or an empty list if none found.
    """
    # clean the banner for the keyword search (replace slashes with spaces)
    # "Apache/2.4.41" becomes "Apache 2.4.41"
    clean_banner = banner.replace("/", " ").replace("_", " ")
    
    # only want few results to avoid overloading the screen
    params = {
        "keywordSearch": clean_banner,
        "resultsPerPage": 3 
    }
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    print(f"[*] Querying NVD database for: '{clean_banner}'...")
    
    # loop for retry mechanism
    for attempt in range(max_retries):
        try:
            # make the HTTP GET request to NVD API
            response = requests.get(url, params=params, timeout=10)
            
            # handle rate limiting
            if response.status_code == 403:
                print("[-] NVD API rate limit exceeded. Please wait and try again.")
                return []
                
            # handle server overload
            if response.status_code in [502, 503, 504]:
                wait_time = 2 ** attempt  # 1s, 2s, 4s...
                print(f"[-] NVD API is struggling (Error {response.status_code}). Retrying in {wait_time}s...")
                time.sleep(wait_time)
                continue # skip the rest of the loop and try again
                
            response.raise_for_status()
            data = response.json()
            
            # parse json response
            cve_list = []
            vulnerabilities = data.get("vulnerabilities", [])
            
            for vuln in vulnerabilities:
                cve_item = vuln.get("cve", {})
                cve_id = cve_item.get("id", "Unknown CVE")
                
                # get english description
                descriptions = cve_item.get("descriptions", [])
                desc_text = next((desc.get("value") for desc in descriptions if desc.get("lang") == "en"), "No description.")
                
                # extract cvss score (1.0 to 10.0)
                metrics = cve_item.get("metrics", {})
                cvss_score = "N/A"
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version in metrics:
                        cvss_score = metrics[version][0]["cvssData"]["baseScore"]
                        break

                cve_list.append({
                    "cve_id": cve_id,
                    "score": cvss_score,
                    "description": desc_text[:150] + "..." 
                })
                
            return cve_list
        # catch timeouts and connection errors to trigger a retry
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            wait_time = 2 ** attempt
            print(f"[-] NVD API timed out. Retrying in {wait_time}s...")
            time.sleep(wait_time)
            continue
        except requests.exceptions.RequestException as e:
            print(f"[-] Network error connecting to NVD API: {type(e).__name__}")
            return []

    # if the loop finishes all retries without returning, the server is truly dead today
    print("[-] NVD API failed to respond after multiple attempts. Moving on.")
    return []

if __name__ == "__main__":
    target = Get_Local_Subnet()
    print(f"[*] Dynamically detected target subnet: {target}")
    
    mongo_uri = os.getenv("MONGO_URI") # Pulled from K8s ConfigMap
    
    print(f"[*] Starting scan against target: {target}")
    
    # 1. Run scanner (assuming execution logic populates the scan_results dict)
    ips = Scan_Network(target)
    scan_results = {}
    # ... existing loop that populates scan_results ...
    
    # 2. Push to MongoDB
    if mongo_uri:
        print(f"[*] Connecting to database at {mongo_uri}...")
        client = pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        
        # Create a database called 'SecOps' and a collection called 'NetworkScans'
        db = client["SecOps"]
        collection = db["NetworkScans"]
        
        # Format the payload for the database
        payload = {
            "scan_date": datetime.utcnow().isoformat(),
            "target_subnet": target,
            "results": scan_results
        }
        
        # Insert the data
        collection.insert_one(payload)
        print("[+] Scan data successfully saved to MongoDB!")
    else:
        print("[-] No MONGO_URI found. Skipping database injection.")

'''

scan_results = {}
ips = scan_network()
for ip in ips:
    open_ports = []
    # using ThreadPoolExecutor to run scans concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        # map the target IP and ports to the scanning function
        futures = [executor.submit(scan_port, ip, port) for port in ports]
        
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
    if open_ports:
        open_ports.sort()
        print(f"{ip} is running services: {open_ports}")
    else:
        print(f"{ip} is running with no open ports")

    # add the data to our dictionary
    scan_results[ip] = {
        "status": "online",
        "open_ports": open_ports
    }

# save results to JSON file
print(f"\nSaving results to {output_file}...")
with open(output_file, "w") as outfile:
    # indent=4 makes the JSON file pretty and readable
    json.dump(scan_results, outfile, indent=4)

'''



