"""
Burp Suite handoff helpers.

Burp Suite itself cannot be embedded. HelixAudit exports:
- URL scope list for Target / sitemap paste
- JSON package for extensions / REST API
- Optional push to Burp REST API (if BURP_API_URL configured)
"""

from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse
import httpx


def _unique_urls(assets: list, findings: list, target: str) -> List[str]:
    urls: List[str] = []
    seen: Set[str] = set()

    def add(u: Optional[str]):
        if not u or not isinstance(u, str):
            return
        u = u.strip()
        if not u.startswith("http"):
            return
        if u in seen:
            return
        seen.add(u)
        urls.append(u)

    add(target if target.startswith("http") else f"https://{target}")
    for a in assets or []:
        val = getattr(a, "value", None) or (a.get("value") if isinstance(a, dict) else None)
        typ = getattr(a, "asset_type", None) or (a.get("asset_type") if isinstance(a, dict) else None)
        if typ in ("url", "page", "path", "auth_page") or (val and str(val).startswith("http")):
            add(str(val))
        elif typ == "subdomain" and val:
            add(f"https://{val}")
    for f in findings or []:
        loc = getattr(f, "location", None) or (f.get("location") if isinstance(f, dict) else None)
        add(loc)
    return urls[:500]


def build_burp_scope(urls: List[str], target: str) -> Dict[str, Any]:
    """Burp-like include scope from discovered URLs."""
    hosts = set()
    for u in urls:
        try:
            p = urlparse(u)
            if p.hostname:
                hosts.add(p.hostname.lower())
        except Exception:
            continue
    if not hosts:
        h = urlparse(target if "://" in target else f"https://{target}").hostname
        if h:
            hosts.add(h.lower())

    include = []
    for h in sorted(hosts):
        include.append({
            "enabled": True,
            "protocol": "any",
            "host": h,
            "port": "",
            "file": "",
        })
    return {
        "target": {
            "scope": {
                "advanced_mode": False,
                "exclude": [],
                "include": include,
            }
        }
    }


def build_burp_package(scan, assets, findings) -> Dict[str, Any]:
    target = scan.target
    urls = _unique_urls(assets, findings, target)
    scope = build_burp_scope(urls, target)
    issues = []
    for f in findings or []:
        sev = (getattr(f, "severity", None) or "info").lower()
        if (getattr(f, "category", None) or "") in ("Executive Summary", "VAPT-Coverage-Matrix", "VAPT-Manual"):
            continue
        issues.append({
            "name": getattr(f, "title", None) or "Finding",
            "severity": sev,
            "url": getattr(f, "location", None) or target,
            "description": (getattr(f, "evidence", None) or "")[:1000],
            "remediation": (getattr(f, "remediation", None) or "")[:500],
            "category": getattr(f, "category", None),
        })
    return {
        "tool": "HelixAudit",
        "scan_id": getattr(scan, "id", None),
        "target": target,
        "urls": urls,
        "url_list_text": "\n".join(urls),
        "burp_scope_json": scope,
        "issues": issues[:200],
        "instructions": [
            "1. Open Burp Suite → Target → Scope.",
            "2. Use 'Use advanced scope control' and import hosts from burp_scope_json, or paste domains manually.",
            "3. Target → Site map → right-click → Add to scope / spider from url_list_text.",
            "4. Optional: run Burp Scanner only on in-scope items (authorized targets only).",
            "5. If BURP_API_URL is set, POST /scans/{id}/burp/push sends URLs to Burp REST API.",
        ],
    }


async def push_urls_to_burp_api(
    api_base: str,
    urls: List[str],
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Best-effort push to Burp REST API style endpoints.
    Common community setups expose something like:
      POST {api}/burp/target/scope
      POST {api}/burp/scanner/scans/new
    Exact paths vary by extension — we try a few.
    """
    base = api_base.rstrip("/")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
        headers["X-API-Key"] = api_key

    results = []
    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        # Add each URL as target (extension-dependent)
        for path in ("/burp/target/scope", "/v0.1/scope", "/scope"):
            try:
                r = await client.put(base + path, json={"urls": urls[:50]}, headers=headers)
                results.append({"path": path, "status": r.status_code, "body": (r.text or "")[:200]})
                if r.status_code < 400:
                    break
            except Exception as e:
                results.append({"path": path, "error": str(e)[:200]})

        for path in ("/burp/scanner/scans/new", "/v0.1/scan", "/scan"):
            try:
                r = await client.post(base + path, json={"urls": urls[:20]}, headers=headers)
                results.append({"path": path, "status": r.status_code, "body": (r.text or "")[:200]})
                if r.status_code < 400:
                    break
            except Exception as e:
                results.append({"path": path, "error": str(e)[:200]})

    ok = any(isinstance(x.get("status"), int) and x["status"] < 400 for x in results)
    return {"ok": ok, "attempts": results, "urls_sent": urls[:50]}
