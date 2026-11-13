"""
Authenticated scanning — form login + session deep crawl.
Authorized use only.
"""

import re
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urljoin, urlparse, urldefrag
import httpx

AUTH_PATHS = [
    "/", "/home", "/dashboard", "/app", "/panel", "/admin", "/administrator",
    "/profile", "/account", "/settings", "/user", "/users", "/me",
    "/api", "/api/user", "/api/me", "/api/v1/user", "/api/v1/me",
    "/orders", "/transactions", "/wallet", "/notifications",
    "/reports", "/files", "/upload", "/exports",
]


def _extract_title(html: str) -> Optional[str]:
    m = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.I | re.S)
    return m.group(1).strip()[:200] if m else None


def _still_looks_like_login(url: str, html: str) -> bool:
    low = (html or "").lower()
    u = (url or "").lower()
    has_pwd = 'type="password"' in low or "type='password'" in low
    loginish = any(x in u for x in ["login", "signin", "auth"])
    return has_pwd and (loginish or "login" in low[:2000])


async def attempt_form_login(
    base_url: str,
    username: str,
    password: str,
    login_url: Optional[str] = None,
) -> Tuple[Optional[httpx.AsyncClient], Dict[str, Any]]:
    info: Dict[str, Any] = {
        "success": False,
        "login_url": None,
        "message": "",
        "status_code": None,
        "final_url": None,
    }

    if not base_url.startswith("http"):
        base_url = "https://" + base_url

    headers = {"User-Agent": "HelixAudit/1.4 (Authorized Authenticated Scanner)"}
    client = httpx.AsyncClient(follow_redirects=True, timeout=20.0, verify=False, headers=headers)

    try:
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        candidates = []
        if login_url:
            candidates.append(login_url if login_url.startswith("http") else urljoin(origin + "/", login_url.lstrip("/")))
        for path in ["/login", "/signin", "/auth/login", "/user/login", "/account/login", "/admin/login", "/wp-login.php"]:
            candidates.append(urljoin(origin + "/", path.lstrip("/")))
        candidates.insert(0, base_url)

        login_page_url = None
        login_html = ""
        for url in candidates:
            try:
                resp = await client.get(url)
                text = resp.text or ""
                if 'type="password"' in text.lower() or "type='password'" in text.lower():
                    login_page_url = str(resp.url)
                    login_html = text
                    break
            except Exception:
                continue

        if not login_page_url:
            info["message"] = "No login form with password field found"
            await client.aclose()
            return None, info

        info["login_url"] = login_page_url
        form_action = login_page_url
        user_field, pass_field = "username", "password"

        action_match = re.search(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', login_html, re.I)
        if action_match:
            form_action = urljoin(login_page_url, action_match.group(1) or "")

        for name in re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>', login_html, re.I):
            lname = name.lower()
            if any(x in lname for x in ["user", "email", "login", "name"]) and "pass" not in lname:
                user_field = name
                break
        for name in re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>', login_html, re.I):
            if "pass" in name.lower():
                pass_field = name
                break

        data = {user_field: username, pass_field: password}
        csrf = re.search(
            r'<input[^>]+name=["\']([^"\']*(?:csrf|token|_token)[^"\']*)["\'][^>]*value=["\']([^"\']*)["\']',
            login_html, re.I,
        )
        if csrf:
            data[csrf.group(1)] = csrf.group(2)

        resp = await client.post(form_action, data=data)
        info["status_code"] = resp.status_code
        info["final_url"] = str(resp.url)
        final_html = resp.text or ""

        if _still_looks_like_login(str(resp.url), final_html):
            info["success"] = False
            info["message"] = "Login appears to have failed (still on login-like page)"
            return client, info

        cookie_names = list(client.cookies.keys())
        info["success"] = True
        info["message"] = "Login appears successful (heuristic)"
        info["cookies"] = cookie_names
        return client, info

    except Exception as e:
        info["message"] = f"Login error: {str(e)[:200]}"
        try:
            await client.aclose()
        except Exception:
            pass
        return None, info


async def authenticated_crawl(
    client: httpx.AsyncClient,
    start_url: str,
    max_pages: int = 25,
) -> List[Dict[str, Any]]:
    """Deep-ish crawl using authenticated session."""
    if not start_url.startswith("http"):
        start_url = "https://" + start_url
    parsed = urlparse(start_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    base_host = parsed.netloc.lower()

    results: List[Dict[str, Any]] = []
    visited = set()
    queue: List[str] = [urljoin(origin + "/", p.lstrip("/")) for p in AUTH_PATHS]
    queue.insert(0, start_url)

    while queue and len(results) < max_pages:
        url, _ = urldefrag(queue.pop(0))
        if url in visited:
            continue
        if urlparse(url).netloc.lower() != base_host:
            continue
        visited.add(url)
        try:
            resp = await client.get(url, timeout=12.0)
            text = resp.text or ""
            title = _extract_title(text)
            is_login = _still_looks_like_login(str(resp.url), text)
            interesting = any(
                x in str(resp.url).lower()
                for x in ["admin", "dashboard", "api", "user", "setting", "account", "report", "export", "upload"]
            )
            item = {
                "url": str(resp.url),
                "status_code": resp.status_code,
                "authenticated": True,
                "content_length": len(resp.content),
                "title": title,
                "still_login": is_login,
                "interesting": interesting and not is_login,
                "has_forms": "<form" in text.lower(),
            }
            results.append(item)

            # Extract same-host links for a bit more depth
            if len(results) < max_pages:
                for href in re.findall(r'href=["\']([^"\'#]+)["\']', text[:80000], re.I)[:30]:
                    full = urljoin(str(resp.url), href)
                    full, _ = urldefrag(full)
                    if urlparse(full).netloc.lower() == base_host and full not in visited:
                        if any(x in full.lower() for x in ["/api", "/admin", "/dashboard", "/user", "/account", "/setting", "/report"]):
                            queue.append(full)
        except Exception as e:
            results.append({"url": url, "error": str(e)[:120], "authenticated": True})

    return results


def auth_findings_from_pages(pages: List[Dict[str, Any]], login_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert auth crawl into structured findings with exposure tags."""
    out: List[Dict[str, Any]] = []
    if not login_info.get("success"):
        out.append({
            "title": "Authenticated scan: login failed or not confirmed",
            "severity": "info",
            "category": "Authenticated Scanning",
            "evidence": str(login_info)[:800],
            "location": login_info.get("login_url") or "",
            "remediation": "Verify credentials and login URL. Auth depth requires successful session.",
            "exposure": "auth",
        })
        return out

    out.append({
        "title": "Authenticated session established",
        "severity": "info",
        "category": "Authenticated Scanning",
        "evidence": f"cookies={login_info.get('cookies')} final={login_info.get('final_url')}",
        "location": login_info.get("final_url") or login_info.get("login_url") or "",
        "remediation": "Ensure session fixation/timeout controls and MFA where appropriate.",
        "exposure": "auth",
    })

    for p in pages:
        if p.get("error"):
            continue
        url = p.get("url") or ""
        code = p.get("status_code")
        if p.get("still_login"):
            continue
        if code == 200 and p.get("interesting"):
            out.append({
                "title": f"Authenticated page accessible: {url}",
                "severity": "medium" if any(x in url.lower() for x in ["admin", "export", "upload", "api"]) else "info",
                "category": "Authenticated Exposure",
                "evidence": str(p)[:600],
                "location": url,
                "remediation": "Verify role-based access; ensure users only see authorized data.",
                "exposure": "auth",
            })
        if code == 200 and "/api" in url.lower():
            out.append({
                "title": f"Authenticated API responds 200: {url}",
                "severity": "medium",
                "category": "Authenticated API",
                "evidence": f"status={code} length={p.get('content_length')}",
                "location": url,
                "remediation": "Confirm authorization checks on API; test IDOR on object IDs under authorization.",
                "exposure": "auth",
            })
    return out
