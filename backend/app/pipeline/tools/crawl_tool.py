from .base import BaseTool
from ..context import PipelineContext
from ...scanners.crawler import crawl_site, directory_discovery


class CrawlTool(BaseTool):
    name = "crawler"
    description = "Crawl + directory discovery"
    order = 40

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        target = ctx.urls[0] if ctx.urls else ctx.target
        pages = await crawl_site(target, max_pages=20, max_depth=2)
        ctx.pages.extend(pages)
        urls = [p.get("url") for p in pages if p.get("url")]
        ctx.merge_urls(urls)

        paths = await directory_discovery(target)
        ctx.paths.extend(paths)
        ctx.merge_urls([p.get("url") for p in paths if p.get("url")])

        for p in paths:
            if p.get("interesting") or p.get("status_code") in [200, 401, 403]:
                path = p.get("path") or ""
                sev = "high" if path in [".env", ".git/HEAD"] else "medium"
                ctx.add_finding(
                    title=f"Interesting path /{path} [{p.get('status_code')}]",
                    severity=sev,
                    category="Content Discovery",
                    evidence=str(p),
                    location=p.get("url") or "",
                    remediation="Restrict sensitive paths.",
                    source_tool=self.name,
                )
        ctx.artifacts["pages"] = len(pages)
        ctx.artifacts["paths"] = paths
        return ctx
