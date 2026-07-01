import requests
import time
import os
import re
from datetime import datetime, timezone
from typing import List
from functools import lru_cache
from .models import Vulnerability


def _clean_version(version: str) -> str:
    version = (version or "").strip()
    if not version:
        return ""
    match = re.search(r"\d+(?:[._-]\d+)*(?:[a-z]\d*)?", version, re.IGNORECASE)
    return match.group(0).replace("_", ".") if match else ""


def _version_tokens(version: str):
    clean = _clean_version(version).lower()
    return [int(token) if token.isdigit() else token for token in re.findall(r"\d+|[a-z]+", clean)]


def _compare_versions(left: str, right: str) -> int:
    left_tokens = _version_tokens(left)
    right_tokens = _version_tokens(right)

    for index in range(max(len(left_tokens), len(right_tokens))):
        left_value = left_tokens[index] if index < len(left_tokens) else 0
        right_value = right_tokens[index] if index < len(right_tokens) else 0

        if left_value == right_value:
            continue
        if isinstance(left_value, int) and isinstance(right_value, str):
            return 1
        if isinstance(left_value, str) and isinstance(right_value, int):
            return -1
        return 1 if left_value > right_value else -1

    return 0


def _normalize_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (value or "").lower())


def _product_matches(product: str, vendor: str, cpe_product: str) -> bool:
    product_norm = _normalize_token(product)
    vendor_norm = _normalize_token(vendor)
    cpe_product_norm = _normalize_token(cpe_product)
    if not product_norm:
        return False

    candidates = [value for value in (vendor_norm, cpe_product_norm) if value]
    for value in candidates:
        # Exact match always counts.
        if value == product_norm:
            return True
        # Substring match with guards: the shorter string must be at least
        # 4 characters AND at least 60 % of the longer string's length.
        # This prevents false positives like "php" matching "phpmyadmin"
        # or "ssh" matching "opensshserver".
        shorter, longer = (value, product_norm) if len(value) <= len(product_norm) else (product_norm, value)
        if len(shorter) >= 4 and len(shorter) / len(longer) >= 0.6 and shorter in longer:
            return True
    return False


def _description_text(cve: dict) -> str:
    for description in cve.get("descriptions", []):
        if description.get("lang") == "en":
            return description.get("value", "")
    return ""


def _parse_cve_date(value: str) -> datetime | None:
    if not value:
        return None
    try:
        cleaned = value.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return None


def _is_recent_enough(cve: dict, match_info: dict | None) -> bool:
    if not cve:
        return False

    published = _parse_cve_date(cve.get("published"))
    if published is None:
        return (match_info or {}).get("confidence") == "confirmed"

    now = datetime.now(timezone.utc)
    age_days = (now - published).days
    confidence = (match_info or {}).get("confidence")

    # Hard cap: always drop CVEs older than 3 years.
    if age_days > 365 * 3:
        return False
    # Speculative matches older than 1 year are too noisy to keep.
    if age_days > 365 and confidence != "confirmed":
        return False
    return True


def _is_rejected(cve: dict, description: str) -> bool:
    status = (cve.get("vulnStatus") or "").lower()
    description_head = description.strip().lower()
    return status in {"rejected", "withdrawn"} or description_head.startswith("** reject **")


def _walk_cpe_matches(nodes):
    for node in nodes or []:
        for match in node.get("cpeMatch", []):
            yield match
        yield from _walk_cpe_matches(node.get("children", []))


def _split_cpe(criteria: str) -> dict:
    parts = (criteria or "").split(":")
    if len(parts) < 6:
        return {}
    return {
        "vendor": parts[3].replace("\\", ""),
        "product": parts[4].replace("\\", ""),
        "version": parts[5].replace("\\", ""),
    }


def _range_summary(match: dict, cpe_version: str) -> str:
    parts = []
    if cpe_version and cpe_version not in {"*", "-"}:
        parts.append(cpe_version)
    for key, label in (
        ("versionStartIncluding", ">="),
        ("versionStartExcluding", ">"),
        ("versionEndIncluding", "<="),
        ("versionEndExcluding", "<"),
    ):
        if match.get(key):
            parts.append(f"{label} {match[key]}")
    return " and ".join(parts) if parts else "No precise affected range in NVD"


def _version_in_match(version: str, match: dict, cpe_version: str) -> bool:
    if cpe_version and cpe_version not in {"*", "-"}:
        return _compare_versions(version, cpe_version) == 0

    start_inclusive = match.get("versionStartIncluding")
    start_exclusive = match.get("versionStartExcluding")
    end_inclusive = match.get("versionEndIncluding")
    end_exclusive = match.get("versionEndExcluding")

    if start_inclusive and _compare_versions(version, start_inclusive) < 0:
        return False
    if start_exclusive and _compare_versions(version, start_exclusive) <= 0:
        return False
    if end_inclusive and _compare_versions(version, end_inclusive) > 0:
        return False
    if end_exclusive and _compare_versions(version, end_exclusive) >= 0:
        return False

    return any([start_inclusive, start_exclusive, end_inclusive, end_exclusive])


def _description_group_key(description: str, product: str, severity: str) -> str:
    words = re.findall(r"[a-z]+", description.lower())
    stop_words = {"the", "and", "for", "with", "this", "that", "allows", "allow", "remote", "attackers"}
    useful_words = [word for word in words if word not in stop_words][:10]
    return ":".join([_normalize_token(product), severity.lower(), "-".join(useful_words[:8])])


def _classify_match(cve: dict, product: str, detected_version: str) -> dict | None:
    configurations = cve.get("configurations", [])
    product_matches = []
    imprecise_product_matches = []

    for match in _walk_cpe_matches(configurations):
        if not match.get("vulnerable", True):
            continue

        cpe = _split_cpe(match.get("criteria", ""))
        if not _product_matches(product, cpe.get("vendor", ""), cpe.get("product", "")):
            continue

        affected = _range_summary(match, cpe.get("version", ""))
        product_matches.append(affected)
        if affected == "No precise affected range in NVD":
            imprecise_product_matches.append(affected)

        if _version_in_match(detected_version, match, cpe.get("version", "")):
            return {
                "confidence": "confirmed",
                "match_basis": "Detected product and version match an affected NVD CPE range.",
                "affected_versions": affected,
                "noise_reason": "",
            }

    if imprecise_product_matches:
        return {
            "confidence": "speculative",
            "match_basis": "Detected product matched NVD data, but NVD did not provide a precise affected-version range.",
            "affected_versions": "No precise affected range in NVD",
            "noise_reason": "Review manually because this match is based on product identity, not a version range.",
        }

    if not configurations:
        return {
            "confidence": "speculative",
            "match_basis": "Keyword match only; NVD did not provide machine-readable affected-version data.",
            "affected_versions": "Unknown",
            "noise_reason": "Review manually because affected-version data was unavailable.",
        }

    return None


# NOTE: lru_cache is per-process memory. This is fine for a single uvicorn
# worker but would cause duplicate NVD calls and wasted memory with multiple
# workers. For multi-worker deployments, swap to a shared cache (e.g. Redis).
@lru_cache(maxsize=128)
def get_cves(product: str, version: str) -> List[Vulnerability]:
    product = (product or "").strip()
    clean_version = _clean_version(version)

    if not product or not clean_version:
        if product:
            print(f"[*] Skipping CVE lookup for {product}: no detected version")
        return []
    
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
        
        params = {"keywordSearch": query, "resultsPerPage": 20}
        response = requests.get(url, params=params, headers=headers, timeout=15)
        
        if response.status_code != 200:
            print(f"[!] NVD API returned {response.status_code}")
            return []

        data = response.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            description = _description_text(cve)
            if _is_rejected(cve, description):
                continue

            match_info = _classify_match(cve, product, clean_version)
            if not match_info or not _is_recent_enough(cve, match_info):
                continue
            
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

            cves.append(Vulnerability(
                id=cve_id,
                severity=severity,
                cvss=cvss_score,
                description=description,
                status=cve.get("vulnStatus", "Analyzed"),
                confidence=match_info["confidence"],
                match_basis=match_info["match_basis"],
                affected_versions=match_info["affected_versions"],
                detected_version=clean_version,
                group_key=_description_group_key(description, product, severity),
                noise_reason=match_info["noise_reason"],
            ))
        
        return cves
    
    except Exception as e:
        print(f"[!] CVE lookup failed: {e}")
        return []
