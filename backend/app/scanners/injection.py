"""
Stronger safe injection detection (still NOT a full exploit engine).
Uses benign probes + error signatures + reflection checks.
"""

import httpx
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse


SQL_ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "mysqli_", "pg_query", "sqlite3.operationalerror",
    "unclosed quotation mark", "odbc sql", "ora-01756", "ora-00933",
    "syntax error", "sqlstate", "you have an error in your sql",
    "warning: mysql", "pg_plan", "microsoft ole db", "odbc driver",
    "jpa exception", "sqlcommand", "sqlite exception",
]

SQL_PROBES = ["'", "\"", "' OR '1'='1", "1/0", "') OR ('1'='1"]
XSS_MARKER = "helixauditxss042"
XSS_PROBES = [
    XSS_MARKER,
    f"<div>{XSS_MARKER}</div>",
    f"\"'{XSS_MARKER}",
]
PARAM_NAMES = ["id", "q", "search", "s", "query", "page", "product_id", "user", "name", "keyword", "cat", "category"]


async def _get(client: httpx.AsyncClient, url: str) -> str:
    try:
        r = await client.get(url, timeout=8.0)
        return r.text or ""
    except Exception:
        return ""


async def check_sqli_surface(client: httpx.AsyncClient, base_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    pages = [base_url]
    for path in ["/", "/search", "/product", "/item", "/page", "/index.php", "/api"]:
        pages.append(urljoin(origin + "/", path.lstrip("/")))

    seen = set()
    for page in pages[:6]:
        for param in PARAM_NAMES:
            for probe in SQL_PROBES:
                key = f"{page}|{param}|{probe}"
                if key in seen:
                    continue
                seen.add(key)
                sep = "&" if "?" in page else "?"
                # minimal encoding via httpx params would be better; keep simple
                test_url = f"{page}{sep}{param}={probe}"
                body = (await _get(client, test_url)).lower()
                for sig in SQL_ERROR_SIGNATURES:
                    if sig in body:
                        findings.append({
                            "title": f"Possible SQL injection surface on '{param}'",
                            "severity": "high",
                            "category": "A05:2025 - Injection",
                            "evidence": f"DB error signature '{sig}' after probe on {test_url[:200]}",
                            "location": test_url[:400],
                            "remediation": "Use parameterized queries/ORM. Never concatenate user input into SQL. Add WAF + input validation."
                        })
                        return findings
    return findings


async def check_xss_reflection(client: httpx.AsyncClient, base_url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    origin = f"{parsed.scheme}://{parsed.netloc}"

    for path in ["/", "/search", "/index.php"]:
        for param in ["q", "search", "s", "query", "name", "keyword", "error"]:
            for probe in XSS_PROBES:
                try:
                    url = f"{urljoin(origin + '/', path.lstrip('/'))}?{param}={probe}"
                    body = await _get(client, url)
                    if XSS_MARKER in body:
                        # rough context hint
                        ctx = "body"
                        low = body.lower()
                        idx = low.find(XSS_MARKER.lower())
                        snippet = body[max(0, idx - 40): idx + 40] if idx >= 0 else ""
                        if "<script" in snippet.lower():
                            ctx = "near script tag"
                        findings.append({
                            "title": f"Reflected XSS surface on '{param}' ({ctx})",
                            "severity": "medium",
                            "category": "A05:2025 - Injection",
                            "evidence": f"Marker reflected from {url[:200]} | snippet={snippet[:80]}",
                            "location": url[:400],
                            "remediation": "Apply context-aware output encoding. Use strict Content-Security-Policy. Validate/encode all reflected input."
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
