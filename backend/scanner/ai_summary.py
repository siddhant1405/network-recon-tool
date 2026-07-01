import json
import os
import re
from typing import Any, Dict, List

import requests


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": 1}


def _empty_severity_counts() -> Dict[str, int]:
    return {severity.lower(): 0 for severity in SEVERITIES}


def _excerpt(text: str, limit: int = 140) -> str:
    compact = re.sub(r"\s+", " ", (text or "").strip())
    return compact[:limit].rstrip(" .")


def _build_notable_findings(hosts: List[Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for host in hosts:
        for port in getattr(host, "ports", []):
            service_name = (getattr(port, "service", "") or getattr(port, "product", "") or "unknown").strip()
            for cve in getattr(port, "cves", []):
                severity = (getattr(cve, "severity", "UNKNOWN") or "UNKNOWN").upper()
                confidence = (getattr(cve, "confidence", "unknown") or "unknown").lower()
                noise_reason = (getattr(cve, "noise_reason", "") or "").strip()
                if severity not in SEVERITY_RANK and not noise_reason and confidence == "confirmed":
                    continue
                findings.append({
                    "id": getattr(cve, "id", "unknown"),
                    "severity": severity,
                    "confidence": confidence,
                    "service": service_name or "unknown service",
                    "detail": _excerpt(getattr(cve, "description", "")),
                    "noise_reason": noise_reason,
                    "detected_version": getattr(cve, "detected_version", "") or getattr(port, "version", ""),
                })

    findings.sort(
        key=lambda item: (
            SEVERITY_RANK.get(item["severity"], 0),
            0 if item["confidence"] == "confirmed" else 1,
            0 if item["noise_reason"] else 1,
        ),
        reverse=True,
    )
    return findings[:5]


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
    confidence_counts = {"confirmed": 0, "speculative": 0, "unknown": 0}
    likely_noise = []

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

                confidence = (getattr(cve, "confidence", "unknown") or "unknown").lower()
                if confidence not in confidence_counts:
                    confidence = "unknown"
                confidence_counts[confidence] += 1

                noise_reason = getattr(cve, "noise_reason", "")
                if noise_reason and len(likely_noise) < 5:
                    likely_noise.append({
                        "id": getattr(cve, "id", "unknown"),
                        "reason": noise_reason[:140],
                    })

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
    notable_findings = _build_notable_findings(hosts)

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
        "match_confidence_counts": confidence_counts,
        "likely_noise": likely_noise,
        "notable_findings": notable_findings,
    }


def fallback_explanation(summary: Dict[str, Any], reason: str = "fallback") -> Dict[str, Any]:
    total_cves = summary.get("known_cve_matches", 0)
    critical_findings = summary.get("critical_findings", 0)
    high_findings = summary.get("high_findings", 0)
    open_ports = summary.get("open_port_count", 0)
    confidence_counts = summary.get("match_confidence_counts", {})
    speculative_count = confidence_counts.get("speculative", 0)
    likely_noise = summary.get("likely_noise", [])
    notable_findings = summary.get("notable_findings", [])
    highlight = notable_findings[0] if notable_findings else None

    highlight_sentence = ""
    if highlight:
        detail = _excerpt(highlight.get("detail", ""))
        if detail:
            highlight_sentence = f"One notable result was {highlight['id']} for {highlight['service']}: {detail}."
        else:
            highlight_sentence = f"One notable result was {highlight['id']} for {highlight['service']}."

    noise_sentence = ""
    if likely_noise:
        noise_sentence = f" {len(likely_noise)} finding(s) were flagged as likely noise because the evidence looks weak or the affected range seems outdated."

    if critical_findings:
        headline = "Critical issues need review."
        explanation = (
            f"The scan found one or more critical CVE matches. {highlight_sentence} "
            f"Treat these as priority review items, but remember they are still matches from public vulnerability data, not proof of compromise.{noise_sentence}"
        )
        actions = [
            "Update or disable the affected service if it is not needed.",
            "Confirm whether the detected version is actually installed and reachable.",
            "Restrict access to trusted devices until reviewed.",
        ]
    elif high_findings:
        headline = "Review recommended, but no critical findings were detected."
        explanation = (
            f"Some high-severity CVE matches were found. {highlight_sentence} "
            f"These should be reviewed, but a CVE match does not automatically mean the device is actively vulnerable or compromised.{noise_sentence}"
        )
        actions = [
            "Keep the OS, browser, and development tools updated.",
            "Close services you do not actively use.",
            "Review the listed findings when convenient.",
        ]
    elif total_cves:
        headline = "Your system has CVE matches that need context."
        explanation = (
            f"The scan found known CVE matches from public databases, but no critical findings. {highlight_sentence} "
            f"{speculative_count} match(es) are lower-confidence and may be noise if the detected version does not truly match the affected range.{noise_sentence}"
        )
        actions = [
            "No urgent action is required right now.",
            "Keep your software updated.",
            "Review exposed services if this device is reachable from untrusted networks.",
        ]
    elif open_ports:
        headline = "Open services were found, with no CVE matches in this scan."
        explanation = (
            "The scan found services accepting network connections. That is not automatically bad, "
            "but each open port should be expected and limited to trusted networks when possible."
        )
        actions = [
            "Confirm each open port is needed.",
            "Disable services you do not use.",
            "Use Deep mode if you want slower version and CVE matching.",
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
            "Call out when findings look likely to be low-confidence noise.",
            "Prefer confirmed-version matches over speculative product-only matches.",
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
