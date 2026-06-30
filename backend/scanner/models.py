from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass
class Vulnerability:
    id: str
    severity: str
    description: str
    cvss: float = 0.0
    summary: str = ""

@dataclass
class ServiceFingerprint:
    http_server: Optional[str] = None
    http_powered_by: Optional[str] = None
    ssl_issuer: Optional[str] = None
    ssl_subject: Optional[str] = None
    ssl_expiry: Optional[str] = None
    raw_headers: Dict[str, str] = field(default_factory=dict)

@dataclass
class Port:
    port: int
    protocol: str
    service: str
    state: str
    version: str = ""
    product: str = ""
    cves: List[Vulnerability] = field(default_factory=list)
    fingerprint: Optional[ServiceFingerprint] = None
    summary: str = ""

@dataclass
class Host:
    ip: str
    os: str = "Unknown"
    ports: List[Port] = field(default_factory=list)
    risk_score: float = 0.0
    risk_label: str = "Low"
