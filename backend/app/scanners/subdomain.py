"""
Basic Subdomain Enumeration for HelixAudit Phase 1
Uses multiple passive + light active techniques.
"""

import asyncio
import httpx
import socket
from typing import List, Set
from urllib.parse import urlparse


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
    "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
    "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
    "web", "media", "email", "images", "img", "www1", "intranet", "portal",
    "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3",
    "dns", "search", "staging", "server", "mx1", "chat", "wap", "my", "svn",
    "mail1", "sites", "proxy", "ads", "online", "staging", "api", "app", "dev",
    "stage", "test", "uat", "qa", "prod", "production", "git", "jenkins", "ci"
]


async def resolve_subdomain(subdomain: str, domain: str) -> str | None:
    """Try to resolve a subdomain. Returns full domain if resolves."""
    full = f"{subdomain}.{domain}"
    try:
        loop = asyncio.get_event_loop()
        await loop.getaddrinfo(full, None)
        return full
    except Exception:
        return None


async def enumerate_subdomains(target: str, max_concurrent: int = 30) -> List[str]:
    """
    Enumerate subdomains for a given target (domain or URL).
    Returns list of discovered subdomains.
    """
    parsed = urlparse(target if "://" in target else f"http://{target}")
    domain = parsed.netloc or parsed.path
    domain = domain.split(":")[0].lower().strip()
    
    # Remove www. if present for base domain
    if domain.startswith("www."):
        domain = domain[4:]
    
    discovered: Set[str] = set()
    discovered.add(domain)
    
    # Also try www
    www = f"www.{domain}"
    try:
        loop = asyncio.get_event_loop()
        await loop.getaddrinfo(www, None)
        discovered.add(www)
    except Exception:
        pass
    
    # Concurrent resolution of common subdomains
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def check(sub):
        async with semaphore:
            result = await resolve_subdomain(sub, domain)
            if result:
                discovered.add(result)
    
    tasks = [check(sub) for sub in COMMON_SUBDOMAINS]
    await asyncio.gather(*tasks, return_exceptions=True)
    
    return sorted(list(discovered))
