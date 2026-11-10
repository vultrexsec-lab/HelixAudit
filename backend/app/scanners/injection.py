"""Fast, bounded injection detection probes."""

import httpx
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse


SQL_ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "mysqli_", "pg_query", "sqlite3.operationalerror",
    "unclosed quotation mark", "ora-01756", "syntax error", "sqlstate",
    "you have an error in your sql", "warning: mysql",
]

SQL_PROBES = ["'", "1/0"]
XSS_MARKER = "helixauditxss042"
PARAM_NAMES = ["id", "q", "search", "page"]


async def check_sqli_surface(client: httpx.AsyncClient, base_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    pages = [base_url, urljoin(origin + "/", "search")]

    for page in pages[:2]:
        for param in PARAM_NAMES[:3]:
            for probe in SQL_PROBES:
                sep = "&" if "?" in page else "?"
                test_url = f"{page}{sep}{param}={probe}"
                try:
                    r = await client.get(test_url, timeout=5.0)
                    body = (r.text or "").lower()
                except Exception:
                    continue
                for sig in SQL_ERROR_SIGNATURES:
                    if sig in body:
                        findings.append({
                            "title": f"Possible SQL injection surface on '{param}'",
                            "severity": "high",
                            "category": "A05:2025 - Injection",
                            "evidence": f"DB error signature '{sig}' at {test_url[:180]}",
                            "location": test_url[:400],
                            "remediation": "Use parameterized queries / ORM.",
                        })
                        return findings
    return findings


async def check_xss_reflection(client: httpx.AsyncClient, base_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    for param in ["q", "search", "s"]:
        url = f"{origin}/?{param}={XSS_MARKER}"
        try:
            r = await client.get(url, timeout=5.0)
            if XSS_MARKER in (r.text or ""):
                findings.append({
                    "title": f"Reflected XSS surface on '{param}'",
                    "severity": "medium",
                    "category": "A05:2025 - Injection",
                    "evidence": f"Marker reflected from {url}",
                    "location": url,
                    "remediation": "Encode output; use CSP.",
                })
                return findings
        except Exception:
            continue
    return findings


async def run_injection_detection(client: httpx.AsyncClient, base_url: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    out.extend(await check_sqli_surface(client, base_url))
    out.extend(await check_xss_reflection(client, base_url))
    return out
