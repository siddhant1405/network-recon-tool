import nmap
import concurrent.futures
from typing import List
from .models import Host, Port
from .vuln_lookup import get_cves
from .fingerprint import get_fingerprint
from .risk_engine import calculate_host_risk

SCAN_PROFILES = {
    "fast": {
        "arguments": "-sT -T4 -F --max-retries 1 --host-timeout 45s --open",
        "include_cves": False,
        "include_fingerprints": False,
    },
    "deep": {
        "arguments": "-sV -O -T4 --max-retries 1 --host-timeout 120s --open",
        "include_cves": True,
        "include_fingerprints": True,
    },
}


def _normalize_scan_mode(scan_mode: str) -> str:
    return scan_mode if scan_mode in SCAN_PROFILES else "fast"


def summarize_port(port_num: int, service_name: str, product: str = "", version: str = "") -> str:
    label = (product or service_name or "unknown service").strip()
    version_copy = f" version {version}" if version else ""
    service_key = (service_name or product or "").lower()

    known_services = {
        "http": "This usually means a web server or web application is reachable on this host.",
        "https": "This usually means an encrypted web service is reachable on this host.",
        "ssh": "This usually allows remote command-line login and should be exposed only to trusted users.",
        "rdp": "This usually allows remote desktop access and should not be exposed to untrusted networks.",
        "ms-wbt-server": "This usually indicates Windows Remote Desktop access.",
        "microsoft-ds": "This is commonly Windows file sharing or SMB and is safest on trusted private networks.",
        "netbios-ssn": "This is related to older Windows file sharing and name services.",
        "postgresql": "This is a PostgreSQL database service and should usually be reachable only by trusted apps.",
        "mysql": "This is a MySQL database service and should usually be reachable only by trusted apps.",
        "redis": "This is an in-memory data store and should not be exposed without strict access controls.",
        "domain": "This is DNS service, used to resolve names to network addresses.",
    }

    for key, meaning in known_services.items():
        if key in service_key:
            return f"Port {port_num} is open for {label}{version_copy}. {meaning}"

    return (
        f"Port {port_num} is open for {label}{version_copy}. "
        "An open port means a service is accepting network connections; review whether it is expected."
    )


def summarize_cve(cve, service_name: str, product: str = "", version: str = "") -> str:
    service_label = (product or service_name or "this service").strip()
    severity = (cve.severity or "unknown").upper()

    if severity == "CRITICAL":
        priority = "Treat this as a priority review item."
    elif severity == "HIGH":
        priority = "Review this soon, especially if the service is reachable from untrusted networks."
    elif severity == "MEDIUM":
        priority = "This is worth tracking and patching during normal maintenance."
    elif severity == "LOW":
        priority = "This is usually lower urgency, but still useful awareness."
    else:
        priority = "Confirm the affected product and version before deciding how serious it is."

    version_copy = f" {version}" if version else ""
    return (
        f"{cve.id} is a {severity.lower()} public vulnerability match for {service_label}{version_copy}. "
        f"{priority} A match is not proof this host is exploitable; it means the detected service metadata resembles known vulnerable software."
    )


def scan_single_host(ip: str, scan_mode: str = "fast") -> Host:
    mode = _normalize_scan_mode(scan_mode)
    profile = SCAN_PROFILES[mode]
    scanner = nmap.PortScanner()
    print(f"[*] Scanning {ip} with {mode} profile...")
    
    try:
        scanner.scan(hosts=ip, arguments=profile["arguments"])
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
            
            cves = get_cves(product, version) if profile["include_cves"] else []
            for cve in cves:
                cve.summary = summarize_cve(cve, service_name, product, version)

            fp = get_fingerprint(ip, port_num, service_name) if profile["include_fingerprints"] else None
            
            port_obj = Port(
                port=port_num,
                protocol=proto,
                service=service_name,
                state=service_info.get("state", "unknown"),
                version=version,
                product=product,
                cves=cves,
                fingerprint=fp,
                summary=summarize_port(port_num, service_name, product, version),
            )
            host_data.ports.append(port_obj)
            
    # Calculate risk
    calculate_host_risk(host_data)
    
    return host_data

def scan_targets(targets: List[str], max_workers: int = 10, scan_mode: str = "fast") -> List[Host]:
    mode = _normalize_scan_mode(scan_mode)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {executor.submit(scan_single_host, target, mode): target for target in targets}
        for future in concurrent.futures.as_completed(future_to_host):
            target = future_to_host[future]
            try:
                host_data = future.result()
                results.append(host_data)
            except Exception as exc:
                print(f"[!] {target} generated an exception: {exc}")
                
    return results
