"""
Deeper (still safe) active surface checks for authorized scanning.
"""

import httpx
from typing import List, Dict, Any
from urllib.parse import urlparse, urljoin


async def check_http_methods(client: httpx.AsyncClient, url: str) -> List[Dict[str, Any]]:
    findings = []
    try:
        resp = await client.request("OPTIONS", url, timeout=8.0)
        allow = resp.headers.get("allow", "") or resp.headers.get("Access-Control-Allow-Methods", "")
        if allow:
            dangerous = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow.upper()]
            if dangerous:
                findings.append({
                    "title": f"Potentially dangerous HTTP methods enabled: {', '.join(dangerous)}",
                    "severity": "medium",
                    "category": "A02:2025 - Security Misconfiguration",
                    "evidence": f"Allow: {allow}",
                    "location": url,
                    "remediation": "Disable unnecessary HTTP methods on the server."
                })
    except Exception:
        pass
    return findings


async def check_cors_misconfig(client: httpx.AsyncClient, url: str) -> List[Dict[str, Any]]:
    findings = []
    try:
        resp = await client.get(
            url,
            headers={"Origin": "https://evil-helixaudit-test.com"},
            timeout=8.0,
        )
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")
        if acao == "*":
            findings.append({
                "title": "CORS allows any origin (*)",
                "severity": "medium",
                "category": "A02:2025 - Security Misconfiguration",
                "evidence": f"Access-Control-Allow-Origin: {acao}",
                "location": url,
                "remediation": "Restrict CORS to trusted origins only."
            })
        elif "evil-helixaudit-test.com" in acao:
            sev = "high" if acac.lower() == "true" else "medium"
            findings.append({
                "title": "CORS reflects arbitrary Origin" + (" with credentials" if acac.lower() == "true" else ""),
                "severity": sev,
                "category": "A02:2025 - Security Misconfiguration",
                "evidence": f"ACAO: {acao} | ACAC: {acac}",
                "location": url,
                "remediation": "Do not reflect arbitrary Origin. Avoid ACAC=true with dynamic origins."
            })
    except Exception:
        pass
    return findings


async def check_sensitive_files(client: httpx.AsyncClient, base_url: str) -> List[Dict[str, Any]]:
    findings = []
    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    paths = [
        "/.env", "/.git/HEAD", "/.git/config", "/backup.sql", "/db.sql",
        "/phpinfo.php", "/.ds_store", "/web.config", "/crossdomain.xml",
        "/security.txt", "/.well-known/security.txt", "/server-status",
        "/actuator/health", "/actuator/env", "/api/swagger.json", "/swagger.json",
        "/graphql", "/robots.txt",
    ]
    for path in paths:
        url = origin + path
        try:
            resp = await client.get(url, timeout=6.0, follow_redirects=False)
            if resp.status_code == 200 and len(resp.content) > 0:
                # skip boring robots empty
                body_preview = (resp.text or "")[:200]
                high = any(x in path for x in [".env", ".git", "backup", "phpinfo", "actuator/env", "db.sql"])
                findings.append({
                    "title": f"Accessible sensitive/interesting file: {path}",
                    "severity": "high" if high else "medium",
                    "category": "A01:2025 - Broken Access Control / Information Disclosure",
                    "evidence": f"Status 200, length={len(resp.content)}, preview={body_preview[:80]}",
                    "location": url,
                    "remediation": "Block public access to sensitive files and admin endpoints."
                })
        except Exception:
            continue
    return findings


async def run_active_checks(client: httpx.AsyncClient, url: str) -> List[Dict[str, Any]]:
    results = []
    results.extend(await check_http_methods(client, url))
    results.extend(await check_cors_misconfig(client, url))
    results.extend(await check_sensitive_files(client, url))
    return results
