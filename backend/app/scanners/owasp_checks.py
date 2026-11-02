"""
Phase 4: OWASP Top 10 (2025) oriented checks
Safe, non-destructive assessments for authorized scanning.
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse, urljoin


def check_security_misconfig(headers: Dict[str, str], url: str) -> List[Dict[str, Any]]:
    """A02:2025 Security Misconfiguration related checks."""
    findings = []
    h = {k.lower(): v for k, v in (headers or {}).items()}

    # Missing important headers
    required = {
        "strict-transport-security": ("Missing HSTS (Strict-Transport-Security)", "medium",
                                      "Add Strict-Transport-Security header with appropriate max-age."),
        "content-security-policy": ("Missing Content-Security-Policy", "medium",
                                    "Implement a restrictive Content-Security-Policy."),
        "x-frame-options": ("Missing X-Frame-Options", "medium",
                            "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking."),
        "x-content-type-options": ("Missing X-Content-Type-Options", "low",
                                   "Set X-Content-Type-Options to nosniff."),
        "referrer-policy": ("Missing Referrer-Policy", "low",
                            "Set a strict Referrer-Policy (e.g. strict-origin-when-cross-origin)."),
        "permissions-policy": ("Missing Permissions-Policy", "low",
                               "Define a Permissions-Policy to restrict browser features."),
    }

    for header, (title, sev, rem) in required.items():
        if header not in h:
            findings.append({
                "title": title,
                "severity": sev,
                "category": "A02:2025 Security Misconfiguration",
                "evidence": f"Header '{header}' not present in response",
                "location": url,
                "remediation": rem
            })

    # Dangerous headers / info disclosure
    if "server" in h:
        findings.append({
            "title": f"Server header discloses technology ({h['server'][:80]})",
            "severity": "low",
            "category": "A02:2025 Security Misconfiguration",
            "evidence": f"Server: {h['server']}",
            "location": url,
            "remediation": "Remove or genericize the Server header."
        })

    if "x-powered-by" in h:
        findings.append({
            "title": f"X-Powered-By header present ({h['x-powered-by'][:60]})",
            "severity": "low",
            "category": "A02:2025 Security Misconfiguration",
            "evidence": f"X-Powered-By: {h['x-powered-by']}",
            "location": url,
            "remediation": "Remove X-Powered-By header."
        })

    # Cookies flags (basic)
    set_cookie = h.get("set-cookie", "")
    if set_cookie:
        if "httponly" not in set_cookie.lower():
            findings.append({
                "title": "Cookie without HttpOnly flag detected",
                "severity": "medium",
                "category": "A02:2025 Security Misconfiguration",
                "evidence": set_cookie[:200],
                "location": url,
                "remediation": "Set HttpOnly flag on session cookies."
            })
        if "secure" not in set_cookie.lower() and url.startswith("https"):
            findings.append({
                "title": "Cookie without Secure flag on HTTPS site",
                "severity": "medium",
                "category": "A02:2025 Security Misconfiguration",
                "evidence": set_cookie[:200],
                "location": url,
                "remediation": "Set Secure flag on cookies when serving over HTTPS."
            })

    return findings


def check_sensitive_paths(paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Interesting / potentially sensitive paths (supports multiple OWASP categories)."""
    findings = []
    high_risk = {".env", ".git/HEAD", ".git/config", "phpinfo.php", "server-status", "config", "backup", "debug"}
    medium_risk = {"admin", "login", "dashboard", "wp-admin", "administrator", "api", "console", "swagger", "graphql"}

    for p in paths:
        path = (p.get("path") or "").lower().strip("/")
        status = p.get("status_code")
        url = p.get("url")

        if path in high_risk and status in [200, 403, 401]:
            findings.append({
                "title": f"Sensitive path accessible: /{path} [{status}]",
                "severity": "high" if status == 200 else "medium",
                "category": "A01:2025 Broken Access Control / A02 Security Misconfiguration",
                "evidence": str(p),
                "location": url,
                "remediation": "Restrict access or remove sensitive files/endpoints from public exposure."
            })
        elif path in medium_risk and status == 200:
            findings.append({
                "title": f"Interesting path found: /{path} [200]",
                "severity": "medium",
                "category": "Content Discovery",
                "evidence": str(p),
                "location": url,
                "remediation": "Review access controls and ensure proper authentication is enforced."
            })

    return findings


def check_information_disclosure(text: str, url: str) -> List[Dict[str, Any]]:
    """Basic information disclosure patterns."""
    findings = []
    if not text:
        return findings

    patterns = [
        (r"(?i)(sql syntax|mysql_fetch|pg_query|ora-\d{5}|unclosed quotation mark)", "Possible SQL error message disclosed", "high"),
        (r"(?i)(exception in|stack trace|traceback \(most recent)", "Stack trace / exception disclosed", "medium"),
        (r"(?i)(debug\s*=\s*true|display_errors\s*=\s*on)", "Debug mode indicator found", "medium"),
        (r"(?i)(todo|fixme|hack|xxx).*?(password|secret|key|token)", "Suspicious developer comment", "low"),
    ]

    for pat, title, sev in patterns:
        if re.search(pat, text):
            findings.append({
                "title": title,
                "severity": sev,
                "category": "A02:2025 Security Misconfiguration / Information Disclosure",
                "evidence": f"Pattern matched in response body from {url}",
                "location": url,
                "remediation": "Disable debug output and detailed errors in production. Sanitize error messages."
            })
            break  # one per page is enough

    return findings


def check_basic_auth_forms(text: str, url: str) -> List[Dict[str, Any]]:
    """Detect login forms (useful for later authenticated testing scope)."""
    findings = []
    if not text:
        return findings

    lower = text.lower()
    has_password_field = 'type="password"' in lower or "type='password'" in lower
    has_login_form = has_password_field and ("<form" in lower)

    if has_login_form:
        findings.append({
            "title": "Login form detected",
            "severity": "info",
            "category": "A07:2025 Authentication Failures (Surface)",
            "evidence": "Password input field found inside a form",
            "location": url,
            "remediation": "Ensure strong authentication, rate limiting, MFA, and secure session management. This is informational for scope planning."
        })

    return findings


def run_owasp_surface_checks(
    url: str,
    headers: Dict[str, str] | None,
    body: str | None,
    discovered_paths: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Aggregate safe OWASP-oriented surface checks."""
    results = []
    results.extend(check_security_misconfig(headers or {}, url))
    results.extend(check_sensitive_paths(discovered_paths or []))
    if body:
        results.extend(check_information_disclosure(body, url))
        results.extend(check_basic_auth_forms(body, url))
    return results
