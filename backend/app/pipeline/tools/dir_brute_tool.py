"""Controlled small directory wordlist (rate-limited)."""

import asyncio
import httpx
from urllib.parse import urlparse
from .base import BaseTool
from ..context import PipelineContext
from ...scanners.soft404 import body_hash, is_soft404

WORDLIST = [
    "admin", "login", "dashboard", "api", "uploads", "upload", "files", "backup",
    "private", "internal", "test", "staging", "dev", "config", "server-status",
    ".well-known/security.txt", "actuator", "metrics", "debug",
]


class DirBruteTool(BaseTool):
    name = "dir_brute"
    description = "Controlled directory brute (small wordlist)"
    order = 44

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        parsed = urlparse(ctx.target if "://" in ctx.target else f"https://{ctx.target}")
        origin = f"{parsed.scheme}://{parsed.netloc}"
        headers = {"User-Agent": "HelixAudit-DirBrute/1.8"}
        hits = []
        async with httpx.AsyncClient(follow_redirects=False, timeout=6.0, verify=False, headers=headers) as client:
            baseline = set()
            try:
                home = await client.get(origin + "/")
                baseline.add(body_hash(home.content))
            except Exception:
                pass
            try:
                rnd = await client.get(origin + "/hx-dirbrute-not-exist-777")
                if rnd.status_code == 200:
                    baseline.add(body_hash(rnd.content))
            except Exception:
                pass

            for i, word in enumerate(WORDLIST):
                url = f"{origin}/{word}"
                try:
                    r = await client.get(url)
                except Exception:
                    continue
                if r.status_code not in (200, 301, 302, 401, 403):
                    continue
                if r.status_code == 200 and is_soft404(r.content, r.headers.get("content-type", ""), baseline, r.text or ""):
                    continue
                hits.append({"path": word, "status": r.status_code, "length": len(r.content)})
                ctx.merge_urls([url])
                if i % 5 == 0:
                    await asyncio.sleep(0.05)

        if hits:
            ctx.add_finding(
                title=f"Directory brute hits ({len(hits)})",
                severity="info",
                category="VAPT-Enumeration",
                evidence=str(hits)[:600],
                location=origin,
                remediation="Review non-soft-404 paths for auth requirements.",
                source_tool=self.name,
            )
        ctx.artifacts["dir_brute"] = hits
        ctx.log_tool(self.name, "ok", f"hits={len(hits)}")
        return ctx
