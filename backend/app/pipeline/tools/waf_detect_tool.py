"""Heuristic WAF / protection detection."""

import httpx
from urllib.parse import urlparse
from .base import BaseTool
from ..context import PipelineContext

WAF_MARKERS = [
    ("cloudflare", "Cloudflare"),
    ("cf-ray", "Cloudflare"),
    ("x-sucuri-id", "Sucuri"),
    ("x-akamai", "Akamai"),
    ("server: awselb", "AWS ELB"),
    ("x-amz-cf-", "CloudFront"),
    ("x-cdn", "CDN"),
    ("incap_ses", "Imperva"),
    ("x-iinfo", "Imperva"),
    ("kwcdn", "KeyCDN"),
]


class WafDetectTool(BaseTool):
    name = "waf_detect"
    description = "Heuristic WAF/CDN detection"
    order = 27

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        url = ctx.urls[0] if ctx.urls else ctx.target
        if not url.startswith("http"):
            url = "https://" + url
        headers = {"User-Agent": "HelixAudit-Pipeline/1.6"}
        found = []
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=10.0, verify=False, headers=headers) as client:
                r = await client.get(url)
                blob = " ".join([f"{k}: {v}" for k, v in r.headers.items()]).lower()
                blob += "\n" + (r.text or "")[:2000].lower()
                for marker, name in WAF_MARKERS:
                    if marker in blob and name not in found:
                        found.append(name)
            ctx.artifacts["waf"] = found
            if found:
                ctx.add_finding(
                    title=f"Possible WAF/CDN detected: {', '.join(found)}",
                    severity="info",
                    category="VAPT-Recon",
                    evidence=str(found),
                    location=url,
                    remediation="Account for WAF behavior during manual testing; tune rate limits.",
                    source_tool=self.name,
                )
            else:
                ctx.add_finding(
                    title="No common WAF signatures detected",
                    severity="info",
                    category="VAPT-Recon",
                    evidence="No known markers matched",
                    location=url,
                    remediation="Absence of signatures does not mean unprotected.",
                    source_tool=self.name,
                )
            ctx.log_tool(self.name, "ok", f"waf={found}")
        except Exception as e:
            ctx.log_tool(self.name, "error", str(e)[:200])
        return ctx
