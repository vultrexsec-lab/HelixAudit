"""
Deep Crawling & Content Collection - Phase 2
Basic but effective spider + directory discovery
"""

import asyncio
import httpx
import re
from urllib.parse import urljoin, urlparse, urldefrag
from typing import Set, List, Dict, Any
from collections import deque


COMMON_PATHS = [
    "admin", "login", "wp-admin", "dashboard", "api", "api/v1", "api/v2",
    "robots.txt", "sitemap.xml", ".env", "config", "backup", "test",
    "dev", "staging", "phpinfo.php", "server-status", "security.txt",
    ".git/HEAD", "wp-login.php", "administrator", "user", "users",
    "upload", "uploads", "files", "assets", "static", "js", "css",
    "images", "img", "media", "docs", "documentation", "swagger",
    "graphql", "graphiql", "console", "debug", "trace", "metrics"
]


async def fetch_page(client: httpx.AsyncClient, url: str) -> Dict[str, Any] | None:
    """Fetch a single page and extract useful info."""
    try:
        resp = await client.get(url, timeout=12.0)
        final_url = str(resp.url)
        content_type = resp.headers.get("content-type", "")
        text = resp.text[:100000] if "text" in content_type or "json" in content_type or "javascript" in content_type else ""

        title = None
        if text:
            m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
            if m:
                title = m.group(1).strip()[:200]

        # Extract links
        links = set()
        if text:
            for match in re.finditer(r'href=["\']([^"\']+)["\']', text, re.I):
                href = match.group(1)
                if href.startswith("#") or href.startswith("mailto:") or href.startswith("tel:"):
                    continue
                full = urljoin(final_url, href)
                full, _ = urldefrag(full)
                links.add(full)

            for match in re.finditer(r'src=["\']([^"\']+)["\']', text, re.I):
                src = match.group(1)
                full = urljoin(final_url, src)
                full, _ = urldefrag(full)
                links.add(full)

        return {
            "url": final_url,
            "status_code": resp.status_code,
            "content_type": content_type,
            "title": title,
            "content_length": len(resp.content),
            "links": list(links)[:100],  # limit
            "has_forms": "<form" in text.lower() if text else False,
            "interesting": any(x in final_url.lower() for x in ["admin", "login", "api", "config", ".env", "backup", "upload"])
        }
    except Exception as e:
        return {"url": url, "error": str(e)[:200]}


async def crawl_site(start_url: str, max_pages: int = 25, max_depth: int = 2) -> List[Dict[str, Any]]:
    """
    Simple BFS crawler.
    Stays within the same domain.
    """
    if not start_url.startswith("http"):
        start_url = "https://" + start_url

    parsed_start = urlparse(start_url)
    base_domain = parsed_start.netloc.lower()

    visited: Set[str] = set()
    results: List[Dict[str, Any]] = []
    queue = deque([(start_url, 0)])  # (url, depth)

    headers = {
        "User-Agent": "HelixAudit/0.2 (Authorized Security Scanner)"
    }

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=15.0,
        verify=False,
        headers=headers,
        limits=httpx.Limits(max_connections=10)
    ) as client:

        while queue and len(results) < max_pages:
            url, depth = queue.popleft()
            url, _ = urldefrag(url)

            if url in visited or depth > max_depth:
                continue
            visited.add(url)

            # Same domain only
            if urlparse(url).netloc.lower() != base_domain:
                continue

            page = await fetch_page(client, url)
            if page:
                results.append(page)

                # Add new links to queue
                if depth < max_depth and "links" in page:
                    for link in page.get("links", []):
                        if link not in visited:
                            queue.append((link, depth + 1))

            await asyncio.sleep(0.3)  # polite

    return results


async def directory_discovery(base_url: str) -> List[Dict[str, Any]]:
    """Check common interesting paths."""
    if not base_url.startswith("http"):
        base_url = "https://" + base_url

    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    findings = []
    headers = {"User-Agent": "HelixAudit/0.2 (Authorized Security Scanner)"}

    async with httpx.AsyncClient(follow_redirects=False, timeout=8.0, verify=False, headers=headers) as client:
        tasks = []
        for path in COMMON_PATHS:
            url = urljoin(origin + "/", path)
            tasks.append(check_path(client, url, path))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict) and r.get("status_code") in [200, 301, 302, 403, 401]:
                findings.append(r)

    return findings


async def check_path(client: httpx.AsyncClient, url: str, path: str) -> Dict[str, Any] | None:
    try:
        resp = await client.get(url)
        return {
            "url": str(resp.url),
            "path": path,
            "status_code": resp.status_code,
            "content_length": len(resp.content),
            "interesting": resp.status_code in [200, 403, 401] or path in [".env", "robots.txt", "sitemap.xml", ".git/HEAD"]
        }
    except Exception:
        return None


# ===== Phase 3 helpers =====
async def fetch_and_analyze(client, url: str) -> Dict[str, Any] | None:
    """Fetch page and return text for secrets analysis."""
    try:
        resp = await client.get(url, timeout=12.0)
        content_type = resp.headers.get("content-type", "")
        text = ""
        if any(x in content_type for x in ["text", "json", "javascript", "xml"]):
            text = resp.text[:150000]
        return {
            "url": str(resp.url),
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "text": text,
            "content_type": content_type
        }
    except Exception as e:
        return None
