import nmap
import concurrent.futures
from typing import List
from .models import Host, Port
from .vuln_lookup import get_cves
from .fingerprint import get_fingerprint
from .risk_engine import calculate_host_risk

def scan_single_host(ip: str) -> Host:
    scanner = nmap.PortScanner()
    print(f"[*] Scanning {ip}...")
    
    try:
        scanner.scan(hosts=ip, arguments="-sV -O -T4 --max-retries 1 --open")
    except Exception as e:
        print(f"[!] Scan failed for {ip}: {e}")
        return Host(ip=ip)
        
    if not scanner.all_hosts():
        return Host(ip=ip)
        
    host_data = Host(ip=ip)
    
    # OS detection
    if "osmatch" in scanner[ip] and scanner[ip]["osmatch"]:
        host_data.os = scanner[ip]["osmatch"][0]["name"]
        
    # Ports and services
    for proto in scanner[ip].all_protocols():
        for port_num in scanner[ip][proto].keys():
            service_info = scanner[ip][proto][port_num]
            product = service_info.get("product", "")
            version = service_info.get("version", "")
            service_name = service_info.get("name", "unknown")
            
            cves = get_cves(product, version)
            fp = get_fingerprint(ip, port_num, service_name)
            
            port_obj = Port(
                port=port_num,
                protocol=proto,
                service=service_name,
                state=service_info.get("state", "unknown"),
                version=version,
                product=product,
                cves=cves,
                fingerprint=fp
            )
            host_data.ports.append(port_obj)
            
    # Calculate risk
    calculate_host_risk(host_data)
    
    return host_data

def scan_targets(targets: List[str], max_workers: int = 10) -> List[Host]:
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {executor.submit(scan_single_host, target): target for target in targets}
        for future in concurrent.futures.as_completed(future_to_host):
            target = future_to_host[future]
            try:
                host_data = future.result()
                results.append(host_data)
            except Exception as exc:
                print(f"[!] {target} generated an exception: {exc}")
                
    return results