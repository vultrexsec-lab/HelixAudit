"""
Safe injection *detection* probes (not a full exploit engine).
Sends benign/safe payloads and looks for error signatures / reflection.
Authorized use only.
"""

import httpx
from typing import List, Dict, Any
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin


SQL_ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "mysqli_", "pg_query", "sqlite3.operationalerror",
    "unclosed quotation mark", "odbc", "ora-01756", "syntax error", "sqlstate",
    "you have an error in your sql", "warning: mysql",
]

XSS_REFLECT_MARKER = "helixauditxss042"

# Safe, non-destructive probe values
SQL_PROBES = ["'", "\"", "' OR '1'='1", "1/0"]


async def check_sqli_surface(client: httpx.AsyncClient, base_url: str) -> List[Dict[str, Any]]:
    findings = []
    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    test_paths = [base_url]
    # common param endpoints
    for path in ["/", "/search", "/product", "/item", "/page"]:
        test_paths.append(urljoin(origin + "/", path.lstrip("/")))

    params_to_try = ["id", "q", "search", "page", "product_id", "user"]

    seen = set()
    for page in test_paths[:4]:
        for param in params_to_try:
            for probe in SQL_PROBES:
                key = f"{page}|{param}|{probe}"
                if key in seen:
                    continue
                seen.add(key)
                try:
                    url = page
                    # append query
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}{param}={httpx.QueryParams({param: probe})[param]}"
                    resp = await client.get(test_url, timeout=8.0)
                    body = (resp.text or "").lower()
                    for sig in SQL_ERROR_SIGNATURES:
                        if sig in body:
                            findings.append({
                                "title": f"Possible SQL injection surface (error-based) on param '{param}'",
                                "severity": "high",
                                "category": "A05:2025 - Injection",
                                "evidence": f"Probe caused DB error signature '{sig}' at {test_url[:180]}",
                                "location": test_url[:300],
                                "remediation": "Use parameterized queries / ORM. Never concatenate user input into SQL."
                            })
                            return findings  # one high-signal finding is enough per scan phase
                except Exception:
                    continue
    return findings


async def check_xss_reflection(client: httpx.AsyncClient, base_url: str) -> List[Dict[str, Any]]:
    findings = []
    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    marker = XSS_REFLECT_MARKER
    params = ["q", "search", "s", "query", "name", "keyword"]

    for path in ["/", "/search"]:
        for param in params:
            try:
                url = f"{urljoin(origin + '/', path.lstrip('/'))}?{param}={marker}"
                resp = await client.get(url, timeout=8.0)
                if marker in (resp.text or ""):
                    # check if inside a script-ish context roughly
                    findings.append({
                        "title": f"Reflected XSS surface on parameter '{param}'",
                        "severity": "medium",
                        "category": "A05:2025 - Injection",
                        "evidence": f"Marker reflected in response body from {url}",
                        "location": url,
                        "remediation": "Context-aware output encoding. Prefer strict CSP."
                    })
                    return findings
            except Exception:
                continue
    return findings


async def run_injection_detection(client: httpx.AsyncClient, base_url: str) -> List[Dict[str, Any]]:
    results = []
    results.extend(await check_sqli_surface(client, base_url))
    results.extend(await check_xss_reflection(client, base_url))
    return results
