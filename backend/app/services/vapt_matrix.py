"""
VAPT Pass / Fail / Not-tested matrix + chapter grouping (6-sigma style coverage).
"""

from typing import Any, Dict, List, Optional

# Canonical checks shown in every report (coverage transparency)
CANONICAL_CHECKS = [
    {"id": "recon.subdomain", "chapter": "Reconnaissance", "name": "Subdomain discovery", "tools": ["subfinder", "subdomain_enum"]},
    {"id": "recon.dns_email", "chapter": "Reconnaissance", "name": "DNS email security (SPF/DMARC/MX)", "tools": ["dns_email_security"]},
    {"id": "recon.ports", "chapter": "Reconnaissance", "name": "Port / service scan", "tools": ["port_scan"]},
    {"id": "recon.live", "chapter": "Reconnaissance", "name": "Live host probe", "tools": ["httpx_probe"]},
    {"id": "recon.waf", "chapter": "Reconnaissance", "name": "WAF / CDN fingerprint", "tools": ["waf_detect"]},
    {"id": "recon.tech", "chapter": "Reconnaissance", "name": "Technology fingerprint", "tools": ["tech_detect"]},
    {"id": "config.tls", "chapter": "Configuration", "name": "TLS / certificate", "tools": ["ssl_check"]},
    {"id": "config.https", "chapter": "Configuration", "name": "HTTP to HTTPS redirect", "tools": ["https_redirect"]},
    {"id": "config.headers", "chapter": "Configuration", "name": "Security headers (HSTS/CSP/XFO/…)", "tools": ["owasp_surface"]},
    {"id": "enum.crawl", "chapter": "Enumeration", "name": "Site crawl", "tools": ["crawler"]},
    {"id": "enum.sitemap", "chapter": "Enumeration", "name": "Sitemap discovery", "tools": ["sitemap_enum"]},
    {"id": "enum.api", "chapter": "Enumeration", "name": "API endpoint discovery", "tools": ["api_discover"]},
    {"id": "enum.baseline", "chapter": "Enumeration", "name": "robots.txt / security.txt", "tools": ["baseline_files"]},
    {"id": "enum.paths", "chapter": "Enumeration", "name": "Sensitive path enumeration", "tools": ["vuln_paths", "crawler"]},
    {"id": "va.secrets", "chapter": "Vulnerability Assessment", "name": "Secrets / sensitive data patterns", "tools": ["secrets_scan"]},
    {"id": "va.active", "chapter": "Vulnerability Assessment", "name": "Active surface (CORS/methods/files)", "tools": ["active_checks"]},
    {"id": "va.injection", "chapter": "Vulnerability Assessment", "name": "Injection surface probes (SQLi/XSS)", "tools": ["injection_detect"]},
    {"id": "va.nuclei", "chapter": "Vulnerability Assessment", "name": "Template vulnerability scan (Nuclei)", "tools": ["nuclei"]},
    {"id": "config.cookies", "chapter": "Configuration", "name": "Cookie security flags", "tools": ["cookie_flags"]},
    {"id": "enum.dir_brute", "chapter": "Enumeration", "name": "Controlled directory brute", "tools": ["dir_brute"]},
    {"id": "enum.swagger", "chapter": "Enumeration", "name": "Swagger/OpenAPI discovery", "tools": ["swagger_enum"]},
    {"id": "enum.js", "chapter": "Enumeration", "name": "JS endpoints / cloud URL extraction", "tools": ["js_endpoints"]},
    {"id": "va.upload", "chapter": "Vulnerability Assessment", "name": "File upload form surface", "tools": ["upload_surface"]},
    {"id": "manual.tier_c", "chapter": "Manual (Tier C)", "name": "Expert manual VAPT checklist", "tools": ["tier_c_manual"]},
    {"id": "auth.session", "chapter": "Authenticated Testing", "name": "Authenticated session deep scan", "tools": ["auth_deep_scan"]},
]


def _tool_status_map(tool_logs: List[Dict[str, Any]]) -> Dict[str, str]:
    m = {}
    for log in tool_logs or []:
        name = log.get("tool") or ""
        st = (log.get("status") or "").lower()
        m[name] = st
    return m


def _has_finding(findings: List[Dict[str, Any]], predicates) -> bool:
    for f in findings:
        if predicates(f):
            return True
    return False


def build_check_matrix(
    tool_logs: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    auth_configured: bool = False,
) -> List[Dict[str, Any]]:
    """
    Status meanings:
      pass       — check ran; no material issue found for this control
      fail       — check ran; issue found (medium+ or confirmed)
      info_only  — check ran; only informational notes
      not_tested — tool skipped / not configured
      error      — tool error/timeout
    """
    tmap = _tool_status_map(tool_logs)
    rows = []

    for check in CANONICAL_CHECKS:
        tools = check["tools"]
        statuses = [tmap.get(t) for t in tools if t in tmap]
        # auth special
        if check["id"] == "auth.session":
            if not auth_configured:
                rows.append({
                    **check,
                    "status": "not_tested",
                    "detail": "No credentials provided for authenticated scan",
                })
                continue
            auth_findings = [
                f for f in findings
                if (f.get("extra_data") or {}).get("exposure") == "auth"
                or "auth" in (f.get("category") or "").lower()
            ]
            if any("fail" in (f.get("title") or "").lower() or (f.get("severity") in ("high", "critical", "medium")) for f in auth_findings):
                # medium+ auth exposure
                if any((f.get("severity") in ("high", "critical", "medium")) for f in auth_findings):
                    rows.append({**check, "status": "fail", "detail": "Authenticated findings present"})
                else:
                    rows.append({**check, "status": "pass", "detail": "Auth stage completed"})
            else:
                rows.append({**check, "status": "pass", "detail": "Auth stage completed with no medium+ issues"})
            continue

        if not statuses:
            # tool never logged
            rows.append({**check, "status": "not_tested", "detail": "No tool log for this check"})
            continue

        if all(s == "skipped" for s in statuses):
            rows.append({**check, "status": "not_tested", "detail": f"Tools skipped: {', '.join(tools)}"})
            continue
        if any(s == "error" for s in statuses) and not any(s == "ok" for s in statuses):
            rows.append({**check, "status": "error", "detail": f"Tool error: {', '.join(tools)}"})
            continue

        # Map findings to this check chapter roughly
        chapter = check["chapter"].lower()
        related = []
        for f in findings:
            cat = (f.get("category") or "").lower()
            title = (f.get("title") or "").lower()
            src = ((f.get("extra_data") or {}).get("source_tool") or "").lower()
            if any(t in src for t in tools):
                related.append(f)
            elif check["id"] == "config.headers" and ("header" in title or "hsts" in title or "csp" in title or "x-frame" in title):
                related.append(f)
            elif check["id"] == "va.injection" and "injection" in cat:
                related.append(f)
            elif check["id"] == "recon.ports" and "port" in cat:
                related.append(f)
            elif check["id"] == "config.tls" and ("tls" in cat or "ssl" in cat):
                related.append(f)
            elif check["id"] == "config.https" and "https" in title:
                related.append(f)
            elif check["id"].startswith("enum") and chapter in cat:
                related.append(f)

        material = [f for f in related if (f.get("severity") or "").lower() in ("critical", "high", "medium")]
        if material:
            rows.append({
                **check,
                "status": "fail",
                "detail": f"{len(material)} medium+ finding(s)",
            })
        elif related:
            rows.append({**check, "status": "info_only", "detail": f"{len(related)} info/low note(s)"})
        else:
            rows.append({**check, "status": "pass", "detail": "Ran; no material issues recorded"})

    return rows


def matrix_summary(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    s = {"pass": 0, "fail": 0, "info_only": 0, "not_tested": 0, "error": 0}
    for r in rows:
        st = r.get("status") or "not_tested"
        if st in s:
            s[st] += 1
    return s


def chapter_findings(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Group findings into VAPT report chapters."""
    chapters = {
        "Executive": [],
        "Reconnaissance": [],
        "Configuration": [],
        "Enumeration": [],
        "Vulnerability Assessment": [],
        "Authenticated Testing": [],
        "Other": [],
    }
    for f in findings:
        cat = (f.get("category") or "").lower()
        exp = (f.get("extra_data") or {}).get("exposure")
        title = (f.get("title") or "").lower()
        if cat == "executive summary" or "executive" in title:
            chapters["Executive"].append(f)
        elif exp == "auth" or "authenticated" in cat:
            chapters["Authenticated Testing"].append(f)
        elif any(x in cat for x in ("recon", "technology", "waf", "email", "open port")):
            chapters["Reconnaissance"].append(f)
        elif any(x in cat for x in ("misconfig", "ssl", "tls", "configuration", "header")):
            chapters["Configuration"].append(f)
        elif any(x in cat for x in ("enumer", "content discovery", "api discovery", "baseline", "sitemap")):
            chapters["Enumeration"].append(f)
        elif any(x in cat for x in ("injection", "nuclei", "vulnerability", "access control", "secret", "active")):
            chapters["Vulnerability Assessment"].append(f)
        elif "pipeline" in cat or "vapt-summary" in cat:
            chapters["Other"].append(f)
        else:
            # severity-based soft sort
            if (f.get("severity") or "") in ("critical", "high", "medium"):
                chapters["Vulnerability Assessment"].append(f)
            else:
                chapters["Other"].append(f)
    return chapters
