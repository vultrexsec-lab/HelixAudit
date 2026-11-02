"""
Improved Technology Detection - Render friendly
"""

import httpx
from typing import Dict, Any
from urllib.parse import urlparse


async def detect_technologies(url: str) -> Dict[str, Any]:
    """
    Basic technology fingerprinting.
    Tries HTTPS first, then HTTP. Better error handling.
    """
    original = url
    if not url.startswith("http"):
        candidates = [f"https://{url}", f"http://{url}"]
    else:
        candidates = [url]
        if url.startswith("https://"):
            candidates.append(url.replace("https://", "http://", 1))
        else:
            candidates.append(url.replace("http://", "https://", 1))

    result = {
        "url": original,
        "final_url": None,
        "status_code": None,
        "server": None,
        "powered_by": None,
        "technologies": [],
        "headers": {},
        "title": None,
        "error": None
    }

    headers = {
        "User-Agent": "HelixAudit/0.1 (Authorized Security Scanner; +https://github.com/vultrexsec-lab/HelixAudit)"
    }

    for candidate in candidates:
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=20.0,
                verify=False,
                headers=headers
            ) as client:
                resp = await client.get(candidate)

                result["final_url"] = str(resp.url)
                result["status_code"] = resp.status_code
                result["headers"] = {k: v for k, v in resp.headers.items()}

                server = resp.headers.get("server")
                if server:
                    result["server"] = server
                    result["technologies"].append(f"Server: {server}")

                powered = resp.headers.get("x-powered-by")
                if powered:
                    result["powered_by"] = powered
                    result["technologies"].append(f"X-Powered-By: {powered}")

                # Title
                text = resp.text[:8000]
                lower = text.lower()
                if "<title>" in lower:
                    start = lower.find("<title>") + 7
                    end = lower.find("</title>", start)
                    if end > start:
                        result["title"] = text[start:end].strip()[:200]

                # Simple tech hints
                headers_str = str(result["headers"]).lower()
                if "cloudflare" in headers_str:
                    result["technologies"].append("Cloudflare")
                if "nginx" in str(result.get("server", "")).lower():
                    result["technologies"].append("Nginx")
                if "apache" in str(result.get("server", "")).lower():
                    result["technologies"].append("Apache")
                if "wordpress" in lower or "wp-content" in lower:
                    result["technologies"].append("WordPress")
                if "react" in lower or "__NEXT_DATA__" in text:
                    result["technologies"].append("React/Next.js")
                if "jquery" in lower:
                    result["technologies"].append("jQuery")
                if "shopify" in lower:
                    result["technologies"].append("Shopify")

                # Success - stop trying other schemes
                result["error"] = None
                break

        except Exception as e:
            result["error"] = str(e)
            continue

    return result
