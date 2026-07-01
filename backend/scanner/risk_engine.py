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
            confidence_multiplier = 1.0 if getattr(cve, "confidence", "") == "confirmed" else 0.35
            if sev == "CRITICAL":
                score += 10 * confidence_multiplier
            elif sev == "HIGH":
                score += 7 * confidence_multiplier
            elif sev == "MEDIUM":
                score += 4 * confidence_multiplier
            elif sev in ["LOW", "UNKNOWN"]:
                score += 1 * confidence_multiplier
                
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
