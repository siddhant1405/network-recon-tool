import requests
import time
import os
from typing import List
from functools import lru_cache
from .models import Vulnerability

@lru_cache(maxsize=128)
def get_cves(product: str, version: str) -> List[Vulnerability]:
    if not product and not version:
        return []
    
    clean_version = version.split(" ")[0]
    query = f"{product} {clean_version}".strip()
    print(f"[*] Looking up CVEs for: {query}")
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"User-Agent": "NetworkReconTool/1.0"}
    
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    
    try:
        # Rate limiting: 0.6s with API key (50 reqs/30s), 6s without
        sleep_time = 0.6 if api_key else 6.0
        time.sleep(sleep_time)
        
        params = {"keywordSearch": query, "resultsPerPage": 5}
        response = requests.get(url, params=params, headers=headers, timeout=15)
        
        if response.status_code != 200:
            print(f"[!] NVD API returned {response.status_code}")
            return []

        data = response.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            
            severity = "UNKNOWN"
            cvss_score = 0.0
            metrics = cve.get("metrics", {})
            
            if "cvssMetricV31" in metrics:
                severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                severity = metrics["cvssMetricV2"][0]["baseSeverity"]
                cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in metrics:
                severity = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
                cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            
            descriptions = cve.get("descriptions", [])
            description = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break
            
            cves.append(Vulnerability(
                id=cve_id,
                severity=severity,
                cvss=cvss_score,
                description=description
            ))
        
        return cves
    
    except Exception as e:
        print(f"[!] CVE lookup failed: {e}")
        return []