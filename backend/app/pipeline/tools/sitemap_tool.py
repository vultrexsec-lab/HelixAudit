"""sitemap.xml discovery for content enumeration."""

import re
import httpx
from urllib.parse import urlparse, urljoin
from .base import BaseTool
from ..context import PipelineContext


class SitemapTool(BaseTool):
    name = "sitemap_enum"
    description = "sitemap.xml URL enumeration"
    order = 41

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        parsed = urlparse(ctx.target if "://" in ctx.target else f"https://{ctx.target}")
        origin = f"{parsed.scheme}://{parsed.netloc}"
        urls = [origin + "/sitemap.xml", origin + "/sitemap_index.xml"]
        found = []
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0, verify=False) as client:
            for u in urls:
                try:
                    r = await client.get(u)
                    if r.status_code == 200 and ("<urlset" in r.text or "<sitemapindex" in r.text or "<loc>" in r.text):
                        locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r.text, re.I)[:50]
                        found.extend(locs)
                        ctx.merge_urls(locs)
                        ctx.add_finding(
                            title=f"Sitemap found with {len(locs)} URLs (sample)",
                            severity="info",
                            category="VAPT-Enumeration",
                            evidence=u + " → " + ", ".join(locs[:10]),
                            location=u,
                            remediation="Ensure sensitive paths are not publicly listed in sitemaps.",
                            source_tool=self.name,
                        )
                except Exception:
                    continue
        ctx.artifacts["sitemap_urls"] = found[:50]
        ctx.log_tool(self.name, "ok", f"urls={len(found)}")
        return ctx
