"""
Phase 4 - Expanded OWASP Top 10 (2025) oriented checks
Safe, authorized-use, non-destructive assessments.
"""

import re
import httpx
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse


async def safe_get(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    try:
        return await client.get(url, timeout=10.0)
    except Exception:
        return None


def check_security_misconfig(headers: Dict[str, str], url: str) -> List[Dict[str, Any]]:
    findings = []
    h = {k.lower(): v for k, v in (headers or {}).items()}

    checks = [
        ("strict-transport-security", "Missing HSTS header", "medium",
         "Add Strict-Transport-Security with suitable max-age and includeSubDomains."),
        ("content-security-policy", "Missing Content-Security-Policy", "medium",
         "Implement a restrictive Content-Security-Policy."),
        ("x-frame-options", "Missing X-Frame-Options (Clickjacking risk)", "medium",
         "Set X-Frame-Options to DENY or SAMEORIGIN."),
        ("x-content-type-options", "Missing X-Content-Type-Options", "low",
         "Set X-Content-Type-Options: nosniff."),
        ("referrer-policy", "Missing Referrer-Policy", "low",
         "Set Referrer-Policy (e.g. strict-origin-when-cross-origin)."),
        ("permissions-policy", "Missing Permissions-Policy", "low",
         "Define Permissions-Policy to limit powerful browser features."),
    ]
    for header, title, sev, rem in checks:
        if header not in h:
            findings.append({
                "title": title, "severity": sev,
                "category": "A02:2025 - Security Misconfiguration",
                "evidence": f"Response missing '{header}' header",
                "location": url, "remediation": rem
            })

    if "server" in h:
        findings.append({
            "title": f"Server technology disclosed: {h['server'][:70]}",
            "severity": "low", "category": "A02:2025 - Security Misconfiguration",
            "evidence": f"Server: {h['server']}", "location": url,
            "remediation": "Remove or obfuscate Server header."
        })
    if "x-powered-by" in h:
        findings.append({
            "title": f"X-Powered-By disclosed: {h['x-powered-by'][:50]}",
            "severity": "low", "category": "A02:2025 - Security Misconfiguration",
            "evidence": f"X-Powered-By: {h['x-powered-by']}", "location": url,
            "remediation": "Remove X-Powered-By header."
        })

    # Cookie security
    sc = h.get("set-cookie", "")
    if sc:
        if "httponly" not in sc.lower():
            findings.append({
                "title": "Session cookie without HttpOnly flag",
                "severity": "medium", "category": "A02:2025 - Security Misconfiguration",
                "evidence": sc[:180], "location": url,
                "remediation": "Add HttpOnly flag to session cookies."
            })
        if url.startswith("https") and "secure" not in sc.lower():
            findings.append({
                "title": "Cookie without Secure flag on HTTPS",
                "severity": "medium", "category": "A02:2025 - Security Misconfiguration",
                "evidence": sc[:180], "location": url,
                "remediation": "Add Secure flag to cookies."
            })
        if "samesite" not in sc.lower():
            findings.append({
                "title": "Cookie without SameSite attribute",
                "severity": "low", "category": "A02:2025 - Security Misconfiguration",
                "evidence": sc[:180], "location": url,
                "remediation": "Set SameSite=Lax or Strict on cookies."
            })
    return findings


def check_sensitive_paths(paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    high = {".env", ".git/head", ".git/config", "phpinfo.php", "server-status", "config.yml", "backup", "debug", ".htaccess"}
    medium = {"admin", "login", "dashboard", "wp-admin", "administrator", "api", "console", "swagger", "graphql", "actuator", "metrics"}

    for p in paths or []:
        path = (p.get("path") or "").lower().strip("/")
        status = p.get("status_code")
        url = p.get("url")
        if not path:
            continue
        if path in high and status in [200, 401, 403]:
            findings.append({
                "title": f"Sensitive path exposed: /{path} [{status}]",
                "severity": "high" if status == 200 else "medium",
                "category": "A01:2025 - Broken Access Control / A02 Misconfiguration",
                "evidence": str(p), "location": url,
                "remediation": "Block or remove sensitive files/endpoints from public access."
            })
        elif path in medium and status == 200:
            findings.append({
                "title": f"Interesting administrative/functional path: /{path}",
                "severity": "medium",
                "category": "A01:2025 - Broken Access Control (Surface)",
                "evidence": str(p), "location": url,
                "remediation": "Ensure strong authentication and authorization on this path."
            })
    return findings


def check_info_disclosure(text: str, url: str) -> List[Dict[str, Any]]:
    findings = []
    if not text:
        return findings
    patterns = [
        (r"(?i)(sql syntax|mysql_fetch|pg_query|ora-\d{5}|unclosed quotation mark)", "Possible database error message disclosed", "high"),
        (r"(?i)(exception in thread|stack trace|traceback \(most recent call)", "Stack trace / exception disclosed", "medium"),
        (r"(?i)(display_errors\s*=\s*on|debug\s*=\s*true|APP_DEBUG\s*=\s*true)", "Debug mode indicator found", "medium"),
        (r"(?i)(todo|fixme|hack|xxx).{0,30}(password|secret|key|token)", "Suspicious developer comment with sensitive keyword", "low"),
    ]
    for pat, title, sev in patterns:
        if re.search(pat, text):
            findings.append({
                "title": title, "severity": sev,
                "category": "A02:2025 - Security Misconfiguration / Information Disclosure",
                "evidence": f"Pattern matched in body of {url}",
                "location": url,
                "remediation": "Disable detailed errors and debug mode in production."
            })
    return findings


def check_login_surface(text: str, url: str) -> List[Dict[str, Any]]:
    findings = []
    if not text:
        return findings
    lower = text.lower()
    if ('type="password"' in lower or "type='password'" in lower) and "<form" in lower:
        findings.append({
            "title": "Login / authentication form detected",
            "severity": "info",
            "category": "A07:2025 - Authentication Failures (Surface)",
            "evidence": "Password field found inside a form",
            "location": url,
            "remediation": "Ensure MFA, rate-limiting, secure session management and account lockout are in place."
        })
    return findings


async def check_open_redirect_surface(client: httpx.AsyncClient, base_url: str) -> List[Dict[str, Any]]:
    """Basic open-redirect parameter surface detection (safe)."""
    findings = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    test_params = ["url", "redirect", "next", "return", "returnTo", "redirect_uri", "continue", "goto"]
    test_value = "https://example.com/helixaudit-test"

    for param in test_params:
        try:
            test_url = f"{origin}/?{param}={test_value}"
            resp = await client.get(test_url, follow_redirects=False, timeout=8.0)
            location = resp.headers.get("location", "")
            if test_value in location or "example.com" in location:
                findings.append({
                    "title": f"Possible open redirect parameter: '{param}'",
                    "severity": "medium",
                    "category": "A01:2025 - Broken Access Control",
                    "evidence": f"Request: {test_url} → Location: {location[:120]}",
                    "location": test_url,
                    "remediation": "Validate and restrict redirect targets to allowed domains only."
                })
                break
        except Exception:
            continue
    return findings


async def check_reflection_surface(client: httpx.AsyncClient, base_url: str) -> List[Dict[str, Any]]:
    """Very light reflection check for potential XSS surface (safe marker)."""
    findings = []
    marker = "helixauditxss12345"
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    try:
        test_url = f"{origin}/?q={marker}&search={marker}&s={marker}"
        resp = await client.get(test_url, timeout=8.0)
        if marker in resp.text:
            findings.append({
                "title": "User input reflected in response (XSS surface)",
                "severity": "medium",
                "category": "A05:2025 - Injection (Reflection Surface)",
                "evidence": f"Marker '{marker}' found reflected in body when sent as parameter",
                "location": test_url,
                "remediation": "Encode all user-controlled output. Implement Content-Security-Policy."
            })
    except Exception:
        pass
    return findings


async def run_full_owasp_checks(
    client: httpx.AsyncClient,
    url: str,
    headers: Dict[str, str],
    body: str,
    discovered_paths: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    results = []
    results.extend(check_security_misconfig(headers or {}, url))
    results.extend(check_sensitive_paths(discovered_paths or []))
    results.extend(check_info_disclosure(body or "", url))
    results.extend(check_login_surface(body or "", url))
    results.extend(await check_open_redirect_surface(client, url))
    results.extend(await check_reflection_surface(client, url))
    return results
