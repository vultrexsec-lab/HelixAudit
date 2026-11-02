"""
Phase 3: Secrets & Sensitive Data Detection
Detects potential passwords, API keys, tokens, and other leaks with evidence.
"""

import re
from typing import List, Dict, Any


# Common secret patterns (high-signal)
SECRET_PATTERNS = [
    # API Keys / Tokens
    (r"(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?", "API Key"),
    (r"(?i)(secret[_-]?key|secret)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-/+]{16,})['\"]?", "Secret Key"),
    (r"(?i)(access[_-]?token|auth[_-]?token|token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{20,})['\"]?", "Access Token"),
    (r"(?i)(bearer\s+)([a-zA-Z0-9_\-\.]{20,})", "Bearer Token"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?", "AWS Secret Key"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Key"),
    (r"sk_test_[0-9a-zA-Z]{24,}", "Stripe Test Key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth Token"),
    (r"xox[baprs]-[0-9a-zA-Z-]{10,}", "Slack Token"),
    
    # Passwords
    (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{4,})['\"]", "Possible Password"),
    (r"(?i)(db[_-]?password|database[_-]?password)\s*[:=]\s*['\"]([^'\"]+)['\"]", "Database Password"),
    
    # Connection strings / URIs
    (r"(?i)(mongodb|postgres|mysql|redis)://[^\s'\"<>]+", "Database Connection String"),
    (r"(?i)jdbc:[a-z0-9]+:[^\s'\"<>]+", "JDBC Connection String"),
    
    # Private keys
    (r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "Private Key"),
    
    # JWT
    (r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*", "JWT Token"),
    
    # Generic high-entropy
    (r"(?i)(client[_-]?secret)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]", "Client Secret"),
]


def find_secrets_in_text(text: str, source: str = "unknown") -> List[Dict[str, Any]]:
    """
    Scan text for potential secrets. Returns list of findings with evidence.
    """
    if not text:
        return []
    
    findings = []
    seen = set()
    
    for pattern, secret_type in SECRET_PATTERNS:
        try:
            for match in re.finditer(pattern, text):
                matched_text = match.group(0)
                # Avoid reporting the same secret multiple times
                key = (secret_type, matched_text[:60])
                if key in seen:
                    continue
                seen.add(key)
                
                # Create safe evidence (truncate long secrets)
                evidence = matched_text
                if len(evidence) > 80:
                    evidence = evidence[:40] + " ... " + evidence[-20:]
                
                findings.append({
                    "type": secret_type,
                    "evidence": evidence,
                    "full_match_length": len(matched_text),
                    "source": source,
                    "severity": 0.85 if secret_type in ["AWS Access Key ID", "GitHub Personal Access Token", "Private Key", "Stripe Live Key"] else 0.7
                })
        except Exception:
            continue
    
    return findings


def analyze_security_headers(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """Check for missing or weak security headers."""
    issues = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    checks = [
        ("strict-transport-security", "Missing HSTS header", "Add Strict-Transport-Security header"),
        ("content-security-policy", "Missing Content-Security-Policy", "Implement a strong CSP"),
        ("x-frame-options", "Missing X-Frame-Options", "Set X-Frame-Options to DENY or SAMEORIGIN"),
        ("x-content-type-options", "Missing X-Content-Type-Options", "Set to nosniff"),
        ("referrer-policy", "Missing Referrer-Policy", "Set a restrictive Referrer-Policy"),
        ("permissions-policy", "Missing Permissions-Policy", "Define Permissions-Policy"),
    ]
    
    for header, title, remediation in checks:
        if header not in headers_lower:
            issues.append({
                "title": title,
                "severity": "medium",
                "remediation": remediation,
                "category": "Security Misconfiguration"
            })
    
    # Server header disclosure
    if "server" in headers_lower:
        server_val = headers_lower["server"]
        if any(x in server_val.lower() for x in ["apache", "nginx", "iis", "tomcat"]):
            issues.append({
                "title": f"Server header discloses technology: {server_val}",
                "severity": "low",
                "remediation": "Remove or obfuscate the Server header",
                "category": "Information Disclosure"
            })
    
    return issues
