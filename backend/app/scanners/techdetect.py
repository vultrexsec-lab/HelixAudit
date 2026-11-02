"""
Basic Technology Detection for HelixAudit Phase 1
"""

import httpx
from typing import Dict, Any, List
from urllib.parse import urlparse


async def detect_technologies(url: str) -> Dict[str, Any]:
    """
    Basic technology fingerprinting using HTTP headers and simple checks.
    """
    if not url.startswith("http"):
        url = "https://" + url
    
    result = {
        "url": url,
        "status_code": None,
        "server": None,
        "powered_by": None,
        "technologies": [],
        "headers": {},
        "title": None,
        "error": None
    }
    
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=15.0, verify=False) as client:
            resp = await client.get(url)
            result["status_code"] = resp.status_code
            result["headers"] = dict(resp.headers)
            
            server = resp.headers.get("server")
            if server:
                result["server"] = server
                result["technologies"].append(f"Server: {server}")
            
            powered = resp.headers.get("x-powered-by")
            if powered:
                result["powered_by"] = powered
                result["technologies"].append(f"X-Powered-By: {powered}")
            
            # Simple title extraction
            text = resp.text[:5000]
            if "<title>" in text.lower():
                start = text.lower().find("<title>") + 7
                end = text.lower().find("</title>", start)
                if end > start:
                    result["title"] = text[start:end].strip()[:200]
            
            # Very basic tech hints
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            body_lower = text.lower()
            
            if "cloudflare" in str(headers_lower):
                result["technologies"].append("Cloudflare")
            if "nginx" in str(result.get("server", "")).lower():
                result["technologies"].append("Nginx")
            if "apache" in str(result.get("server", "")).lower():
                result["technologies"].append("Apache")
            if "wordpress" in body_lower or "wp-content" in body_lower:
                result["technologies"].append("WordPress")
            if "react" in body_lower or "react-dom" in body_lower:
                result["technologies"].append("React")
            if "jquery" in body_lower:
                result["technologies"].append("jQuery")
                
    except Exception as e:
        result["error"] = str(e)
    
    return result
