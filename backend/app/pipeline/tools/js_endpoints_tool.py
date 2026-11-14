"""Extract API-like endpoints and cloud bucket URLs from JavaScript."""

import re
import httpx
from urllib.parse import urljoin, urlparse
from .base import BaseTool
from ..context import PipelineContext

EP_RE = re.compile(r"""(?i)["']((?:https?:\/\/[^"']+|\/)(?:api\/|v[12]\/|graphql)[^"']{0,80})["']""")
S3_RE = re.compile(r"""(?i)(https?://[a-z0-9.\-]+\.s3[.\-][a-z0-9.\-]*\.amazonaws\.com[^\s"'<>]*)""")
GCS_RE = re.compile(r"""(?i)(https?://storage\.googleapis\.com/[a-z0-9.\-_\/]+)""")
AZ_RE = re.compile(r"""(?i)(https?://[a-z0-9.\-]+\.blob\.core\.windows\.net/[^\s"'<>]*)""")


class JsEndpointsTool(BaseTool):
    name = "js_endpoints"
    description = "JS endpoint and cloud bucket URL extraction"
    order = 47

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        parsed = urlparse(ctx.target if "://" in ctx.target else f"https://{ctx.target}")
        origin = f"{parsed.scheme}://{parsed.netloc}"
        endpoints = set()
        buckets = set()
        headers = {"User-Agent": "HelixAudit-Pipeline/1.8"}

        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0, verify=False, headers=headers) as client:
            pages = list(dict.fromkeys((ctx.urls or [origin])[:5]))
            for page in pages:
                try:
                    r = await client.get(page)
                    html = r.text or ""
                except Exception:
                    continue
                for m in EP_RE.findall(html):
                    endpoints.add(urljoin(str(r.url), m))
                for rx in (S3_RE, GCS_RE, AZ_RE):
                    for m in rx.findall(html):
                        buckets.add(m)
                # fetch a few script src
                scripts = re.findall(r"""(?i)<script[^>]+src=["']([^"']+)["']""", html)[:5]
                for src in scripts:
                    js_url = urljoin(str(r.url), src)
                    try:
                        jr = await client.get(js_url)
                        body = jr.text or ""
                    except Exception:
                        continue
                    for m in EP_RE.findall(body):
                        endpoints.add(urljoin(origin, m))
                    for rx in (S3_RE, GCS_RE, AZ_RE):
                        for m in rx.findall(body):
                            buckets.add(m)

        endpoints = sorted(endpoints)[:40]
        buckets = sorted(buckets)[:20]
        ctx.merge_urls(endpoints)
        ctx.artifacts["js_endpoints"] = endpoints
        ctx.artifacts["cloud_buckets"] = buckets

        if endpoints:
            ctx.add_finding(
                title=f"JS-extracted endpoints ({len(endpoints)})",
                severity="info",
                category="VAPT-Enumeration",
                evidence=", ".join(endpoints[:15]),
                location=origin,
                remediation="Review auth on client-visible API routes.",
                source_tool=self.name,
            )
        if buckets:
            ctx.add_finding(
                title=f"Cloud storage URLs referenced ({len(buckets)})",
                severity="medium",
                category="VAPT-Vulnerability Assessment",
                evidence=", ".join(buckets[:10]),
                location=origin,
                remediation="Verify buckets are not publicly listable/writable; use least privilege.",
                source_tool=self.name,
            )
        ctx.log_tool(self.name, "ok", f"endpoints={len(endpoints)} buckets={len(buckets)}")
        return ctx
