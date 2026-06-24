import requests
import ssl
import socket
from datetime import datetime
from .models import ServiceFingerprint

def fingerprint_http(ip: str, port: int, use_https: bool = False) -> ServiceFingerprint:
    fp = ServiceFingerprint()
    protocol = "https" if use_https else "http"
    url = f"{protocol}://{ip}:{port}"
    
    try:
        # Prevent SSL verification errors from killing the request
        response = requests.get(url, timeout=5, verify=False)
        fp.raw_headers = dict(response.headers)
        fp.http_server = response.headers.get("Server")
        fp.http_powered_by = response.headers.get("X-Powered-By")
    except requests.RequestException:
        pass
        
    return fp

def fingerprint_ssl(ip: str, port: int) -> ServiceFingerprint:
    fp = ServiceFingerprint()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    # sometimes binary=False returns empty if verification is None
                    # We might need to manually parse, but for simple use cases:
                    pass
                else:
                    # Subject and Issuer are usually tuples of tuples
                    issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                    subject_dict = dict(x[0] for x in cert.get('subject', []))
                    
                    fp.ssl_issuer = issuer_dict.get('organizationName', issuer_dict.get('commonName'))
                    fp.ssl_subject = subject_dict.get('commonName')
                    fp.ssl_expiry = cert.get('notAfter')
    except Exception:
        pass
        
    return fp

def get_fingerprint(ip: str, port: int, service: str) -> ServiceFingerprint:
    fp = ServiceFingerprint()
    if 'http' in service.lower():
        is_https = 'https' in service.lower() or port == 443 or port == 8443
        http_fp = fingerprint_http(ip, port, use_https=is_https)
        fp.http_server = http_fp.http_server
        fp.http_powered_by = http_fp.http_powered_by
        fp.raw_headers = http_fp.raw_headers
        
        if is_https:
            ssl_fp = fingerprint_ssl(ip, port)
            fp.ssl_issuer = ssl_fp.ssl_issuer
            fp.ssl_subject = ssl_fp.ssl_subject
            fp.ssl_expiry = ssl_fp.ssl_expiry
    elif 'ssl' in service.lower() or port in [443, 8443, 993, 995, 465]:
        ssl_fp = fingerprint_ssl(ip, port)
        fp.ssl_issuer = ssl_fp.ssl_issuer
        fp.ssl_subject = ssl_fp.ssl_subject
        fp.ssl_expiry = ssl_fp.ssl_expiry
        
    return fp
