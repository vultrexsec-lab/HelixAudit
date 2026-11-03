"""
Authenticated scanning foundation.
Performs login (form-based) and reuses session cookies for deeper crawling.
Safe / authorized-use only.
"""

import re
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urljoin, urlparse
import httpx


async def attempt_form_login(
    base_url: str,
    username: str,
    password: str,
    login_url: Optional[str] = None,
) -> Tuple[Optional[httpx.AsyncClient], Dict[str, Any]]:
    """
    Try to detect a login form and authenticate.
    Returns (client_with_cookies, info_dict).
    """
    info: Dict[str, Any] = {
        "success": False,
        "login_url": None,
        "message": "",
        "status_code": None,
    }

    if not base_url.startswith("http"):
        base_url = "https://" + base_url

    headers = {
        "User-Agent": "HelixAudit/0.9 (Authorized Authenticated Scanner)"
    }

    client = httpx.AsyncClient(
        follow_redirects=True,
        timeout=20.0,
        verify=False,
        headers=headers,
    )

    try:
        # 1. Find login page
        candidates = []
        if login_url:
            candidates.append(login_url if login_url.startswith("http") else urljoin(base_url, login_url))
        else:
            parsed = urlparse(base_url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            for path in ["/login", "/signin", "/auth/login", "/user/login", "/account/login", "/wp-login.php", "/admin/login"]:
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

        # 2. Extract form action + field names
        form_action = login_page_url
        user_field = "username"
        pass_field = "password"

        # form action
        action_match = re.search(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>',
            login_html,
            re.I,
        )
        if action_match:
            action = action_match.group(1) or ""
            form_action = urljoin(login_page_url, action)

        # username-like fields
        for name in re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>', login_html, re.I):
            lname = name.lower()
            if any(x in lname for x in ["user", "email", "login", "name"]):
                if "pass" not in lname:
                    user_field = name
                    break

        for name in re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>', login_html, re.I):
            if "pass" in name.lower():
                pass_field = name
                break

        # CSRF token if present
        data = {user_field: username, pass_field: password}
        csrf = re.search(
            r'<input[^>]+name=["\']([^"\']*(?:csrf|token|_token)[^"\']*)["\'][^>]*value=["\']([^"\']*)["\']',
            login_html,
            re.I,
        )
        if csrf:
            data[csrf.group(1)] = csrf.group(2)

        # 3. Submit login
        resp = await client.post(form_action, data=data)
        info["status_code"] = resp.status_code

        # Heuristic success: no password field on result page, or redirect away from login, or set-cookie
        final_text = (resp.text or "").lower()
        still_login = 'type="password"' in final_text and ("login" in str(resp.url).lower() or "signin" in str(resp.url).lower())
        has_session = any("session" in k.lower() or "token" in k.lower() or "auth" in k.lower() for k in resp.cookies.keys())

        if not still_login or has_session or resp.status_code in [302, 303]:
            info["success"] = True
            info["message"] = "Login appears successful (heuristic)"
            info["final_url"] = str(resp.url)
            return client, info

        info["message"] = "Login may have failed (still on login-like page)"
        # Still return client — caller may try limited authenticated crawl
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
    max_pages: int = 15,
) -> List[Dict[str, Any]]:
    """Crawl using an already-authenticated client."""
    from .crawler import crawl_site
    # Re-use existing crawler patterns but with provided client is complex;
    # simple authenticated page fetch list instead.
    results = []
    if not start_url.startswith("http"):
        start_url = "https://" + start_url

    parsed = urlparse(start_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    paths = ["/", "/dashboard", "/home", "/profile", "/account", "/settings", "/admin", "/api", "/user"]

    for path in paths[:max_pages]:
        url = urljoin(origin + "/", path.lstrip("/"))
        try:
            resp = await client.get(url, timeout=12.0)
            results.append({
                "url": str(resp.url),
                "status_code": resp.status_code,
                "authenticated": True,
                "content_length": len(resp.content),
                "title": _extract_title(resp.text or ""),
            })
        except Exception as e:
            results.append({"url": url, "error": str(e)[:120], "authenticated": True})

    return results


def _extract_title(html: str) -> Optional[str]:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if m:
        return m.group(1).strip()[:200]
    return None
