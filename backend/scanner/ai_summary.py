import json
import os
from typing import Any, Dict, List

import requests


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def _empty_severity_counts() -> Dict[str, int]:
    return {severity.lower(): 0 for severity in SEVERITIES}


def build_scan_summary(hosts: List[Any]) -> Dict[str, Any]:
    """Create a compact, sanitized summary for UI copy and optional AI use."""
    severity_counts = _empty_severity_counts()
    total_cves = 0
    critical_findings = 0
    high_findings = 0
    open_ports = 0
    max_risk_score = 0.0
    highest_risk_label = "Low"
    services = {}

    for host in hosts:
        max_risk_score = max(max_risk_score, float(getattr(host, "risk_score", 0.0)))
        if float(getattr(host, "risk_score", 0.0)) == max_risk_score:
            highest_risk_label = getattr(host, "risk_label", "Low")

        for port in getattr(host, "ports", []):
            open_ports += 1
            service_name = (getattr(port, "product", "") or getattr(port, "service", "") or "unknown").strip()
            if service_name:
                normalized_service = service_name[:60]
                services[normalized_service] = services.get(normalized_service, 0) + 1

            for cve in getattr(port, "cves", []):
                total_cves += 1
                severity = (getattr(cve, "severity", "UNKNOWN") or "UNKNOWN").upper()
                severity_key = severity.lower() if severity in SEVERITIES else "unknown"
                severity_counts[severity_key] += 1
                if severity == "CRITICAL":
                    critical_findings += 1
                elif severity == "HIGH":
                    high_findings += 1

    if critical_findings > 0 or max_risk_score > 75:
        risk_label = "Action Needed"
        status_label = "Critical Review Needed"
    elif high_findings > 0 or max_risk_score > 50:
        risk_label = "Review Recommended"
        status_label = "Review Recommended"
    elif total_cves > 0 or open_ports > 0:
        risk_label = "Normal With Warnings"
        status_label = "Normal"
    else:
        risk_label = "Normal"
        status_label = "Normal"

    top_services = [
        {"service": service, "count": count}
        for service, count in sorted(services.items(), key=lambda item: item[1], reverse=True)[:8]
    ]

    return {
        "host_count": len(hosts),
        "open_port_count": open_ports,
        "known_cve_matches": total_cves,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "severity_counts": severity_counts,
        "max_risk_score": round(max_risk_score, 2),
        "highest_risk_label": highest_risk_label,
        "risk_label": risk_label,
        "status_label": status_label,
        "confidence": "Low to Medium" if total_cves else "Medium",
        "match_basis": "Service and version metadata only; raw banners, hostnames, IPs, and full CVE descriptions are not sent to AI.",
        "top_services": top_services,
    }


def fallback_explanation(summary: Dict[str, Any], reason: str = "fallback") -> Dict[str, Any]:
    total_cves = summary.get("known_cve_matches", 0)
    critical_findings = summary.get("critical_findings", 0)
    high_findings = summary.get("high_findings", 0)

    if critical_findings:
        headline = "Critical issues need review."
        explanation = (
            "The scan found one or more critical CVE matches. Treat these as priority review items, "
            "but remember they are still matches from public vulnerability data, not proof of compromise."
        )
        actions = [
            "Update or disable the affected service if it is not needed.",
            "Confirm whether the detected version is actually installed and reachable.",
            "Restrict access to trusted devices until reviewed.",
        ]
    elif high_findings:
        headline = "Review recommended, but no critical findings were detected."
        explanation = (
            "Some high-severity CVE matches were found. These should be reviewed, but a CVE match does "
            "not automatically mean the device is actively vulnerable or compromised."
        )
        actions = [
            "Keep the OS, browser, and development tools updated.",
            "Close services you do not actively use.",
            "Review the listed findings when convenient.",
        ]
    elif total_cves:
        headline = "Your system looks normal, with informational CVE matches."
        explanation = (
            "The scan found known CVE matches from public databases, but no critical findings. Most matches "
            "appear to be based on service names or versions, so they should be treated as awareness items."
        )
        actions = [
            "No urgent action is required right now.",
            "Keep your software updated.",
            "Review exposed services if this device is reachable from untrusted networks.",
        ]
    else:
        headline = "Your system looks normal."
        explanation = "No known CVE matches were found in this scan. Keep software updated as normal."
        actions = [
            "No urgent action is required right now.",
            "Run scans again after major software or network changes.",
        ]

    return {
        "provider": "fallback",
        "model": None,
        "ai_powered": False,
        "status_label": summary.get("status_label", "Normal"),
        "headline": headline,
        "explanation": explanation,
        "recommended_actions": actions,
        "privacy_note": "AI was not used. No scan data was sent to an external model.",
        "source": reason,
    }


def _parse_model_json(content: str) -> Dict[str, Any]:
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        start = content.find("{")
        end = content.rfind("}")
        if start >= 0 and end > start:
            return json.loads(content[start : end + 1])
        raise


def generate_risk_explanation(summary: Dict[str, Any]) -> Dict[str, Any]:
    api_key = os.getenv("GROQ_API_KEY")
    model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

    if not api_key:
        return fallback_explanation(summary, "missing_groq_api_key")

    prompt = {
        "task": "Explain a network scan risk result for a non-technical user.",
        "rules": [
            "Do not claim the device is hacked or safe with certainty.",
            "Explain that CVE matches are possible matches, not confirmed exploitability.",
            "Use calm, clear language.",
            "Do not mention hidden implementation details.",
            "Return JSON only.",
        ],
        "sanitized_scan_summary": summary,
        "output_schema": {
            "status_label": "Normal | Review Recommended | Action Needed | Critical Review Needed",
            "headline": "One short sentence.",
            "explanation": "Two to four short sentences for a common user.",
            "recommended_actions": ["Two to four practical actions."],
        },
    }

    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You explain security scan findings calmly and accurately for non-technical users.",
                    },
                    {"role": "user", "content": json.dumps(prompt)},
                ],
                "temperature": 0.2,
                "response_format": {"type": "json_object"},
            },
            timeout=20,
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        explanation = _parse_model_json(content)

        return {
            "provider": "groq",
            "model": model,
            "ai_powered": True,
            "status_label": explanation.get("status_label", summary.get("status_label", "Normal")),
            "headline": explanation.get("headline", fallback_explanation(summary)["headline"]),
            "explanation": explanation.get("explanation", fallback_explanation(summary)["explanation"]),
            "recommended_actions": explanation.get(
                "recommended_actions",
                fallback_explanation(summary)["recommended_actions"],
            ),
            "privacy_note": "Only a sanitized scan summary was sent to Groq. IPs, hostnames, raw banners, and full CVE descriptions were not sent.",
        }
    except Exception as exc:
        fallback = fallback_explanation(summary, "groq_api_error")
        fallback["error"] = str(exc)
        return fallback
