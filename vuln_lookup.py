import requests
import time

def get_cves(product, version):
    if not product and not version:
        return []
    
    clean_version = version.split(" ")[0]
    query = f"{product} {clean_version}".strip()
    print(f"[*] Looking up CVEs for: {query}")
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    try:
        # Pehle version ke saath try karo
        params = {"keywordSearch": query, "resultsPerPage": 5}
        response = requests.get(url, params=params, timeout=10)
        data = response.json()
        
        # Agar kuch nahi mila toh sirf product name se try karo
        if data.get("totalResults", 0) == 0:
            print(f"[*] No results, retrying with just: {product}")
            params = {"keywordSearch": product, "resultsPerPage": 5}
            response = requests.get(url, params=params, timeout=10)
            data = response.json()
        
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            
            severity = "UNKNOWN"
            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            elif "cvssMetricV2" in metrics:
                severity = metrics["cvssMetricV2"][0]["baseSeverity"]
            
            descriptions = cve.get("descriptions", [])
            description = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break
            
            cves.append({
                "id": cve_id,
                "severity": severity,
                "description": description[:200]
            })
        
        time.sleep(1)
        return cves
    
    except Exception as e:
        print(f"[!] CVE lookup failed: {e}")
        return []