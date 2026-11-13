"""HTTP→HTTPS redirect and HSTS-related transport checks."""

import httpx
from urllib.parse import urlparse
from .base import BaseTool
from ..context import PipelineContext


class HttpsRedirectTool(BaseTool):
    name = "https_redirect"
    description = "HTTP to HTTPS redirect check"
    order = 29

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        host = urlparse(ctx.target if "://" in ctx.target else f"https://{ctx.target}").netloc
        http_url = f"http://{host}/"
        try:
            async with httpx.AsyncClient(follow_redirects=False, timeout=8.0, verify=False) as client:
                r = await client.get(http_url)
            loc = r.headers.get("location", "")
            if r.status_code in (301, 302, 307, 308) and loc.startswith("https://"):
                ctx.add_finding(
                    title="HTTP redirects to HTTPS",
                    severity="info",
                    category="VAPT-Configuration",
                    evidence=f"status={r.status_code} location={loc[:120]}",
                    location=http_url,
                    remediation="Keep HTTPS redirect and enable HSTS.",
                    source_tool=self.name,
                )
            elif r.status_code == 200:
                ctx.add_finding(
                    title="HTTP responds without redirect to HTTPS",
                    severity="medium",
                    category="VAPT-Configuration",
                    evidence=f"status={r.status_code}",
                    location=http_url,
                    remediation="Force HTTPS redirect site-wide.",
                    source_tool=self.name,
                )
            else:
                ctx.add_finding(
                    title=f"HTTP response status {r.status_code}",
                    severity="info",
                    category="VAPT-Configuration",
                    evidence=f"location={loc[:120]}",
                    location=http_url,
                    remediation="Verify transport security configuration.",
                    source_tool=self.name,
                )
            ctx.log_tool(self.name, "ok", f"status={r.status_code}")
        except Exception as e:
            ctx.log_tool(self.name, "error", str(e)[:200])
        return ctx
