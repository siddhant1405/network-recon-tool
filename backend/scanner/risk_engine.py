from .models import Host, Vulnerability

def calculate_host_risk(host: Host) -> Host:
    # Example weights
    # Critical = 10, High = 7, Medium = 4, Low = 1
    # Max possible risk score roughly bounds. Let's say a host with >100 score is capped at 100.
    
    score = 0.0
    
    for port in host.ports:
        # Base risk for exposed service
        score += 0.5 
        
        for cve in port.cves:
            sev = cve.severity.upper()
            if sev == "CRITICAL":
                score += 10
            elif sev == "HIGH":
                score += 7
            elif sev == "MEDIUM":
                score += 4
            elif sev in ["LOW", "UNKNOWN"]:
                score += 1
                
    # Normalize to 0-100 scale (cap at 100)
    score = min(score, 100.0)
    host.risk_score = round(score, 2)
    
    # Assign labels
    if score <= 25:
        host.risk_label = "Low"
    elif score <= 50:
        host.risk_label = "Medium"
    elif score <= 75:
        host.risk_label = "High"
    else:
        host.risk_label = "Critical"
        
    return host
