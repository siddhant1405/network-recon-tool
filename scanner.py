import nmap
import json
from vuln_lookup import get_cves
from report import generate_report

def scan_target(target):
    scanner = nmap.PortScanner()
    
    print(f"[*] Scanning {target}...")
    scanner.scan(hosts=target, arguments="-sV -O --open")
    
    results = []
    
    for host in scanner.all_hosts():
        host_data = {
            "ip": host,
            "os": "Unknown",
            "ports": []
        }
        
        # OS detection
        if "osmatch" in scanner[host] and scanner[host]["osmatch"]:
            host_data["os"] = scanner[host]["osmatch"][0]["name"]
        
        # Port + service info
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto].keys():
                service = scanner[host][proto][port]
                port_data = {
                    "port": port,
                    "protocol": proto,
                    "service": service.get("name", "unknown"),
                    "version": service.get("version", ""),
                    "product": service.get("product", ""),
                    "cves": get_cves(service.get("product", ""), service.get("version", ""))
                }
                host_data["ports"].append(port_data)
        
        results.append(host_data)
    
    return results

if __name__ == "__main__":
    target = input("Enter target IP: ")
    data = scan_target(target)
    print(json.dumps(data, indent=2))
    generate_report(data, target)