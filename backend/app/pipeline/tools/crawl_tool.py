from .base import BaseTool
from ..context import PipelineContext
from ...scanners.crawler import crawl_site, directory_discovery

SENSITIVE = {".env", ".git/HEAD", ".git/config", "backup", "phpinfo.php", "server-status", "actuator", "config.yml"}
ADMINISH = {"admin", "login", "dashboard", "wp-admin", "administrator", "api"}


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
        # Keep assets, but don't spam findings for every 403
        ctx.paths.extend(paths)
        ctx.merge_urls([p.get("url") for p in paths if p.get("url")])

        for p in paths:
            path = (p.get("path") or "").strip("/")
            code = p.get("status_code")
            if code not in (200, 401, 403):
                continue

            # Skip noisy 403 on static/common folders
            if code == 403 and path in {"js", "css", "images", "img", "media", "static", "assets", "files", "robots.txt", "sitemap.xml"}:
                continue

            if path in SENSITIVE:
                sev = "high" if code == 200 else "low"
                title = f"Sensitive path /{path} [{code}]"
            elif path in ADMINISH and code in (200, 401):
                sev = "medium" if code == 200 else "info"
                title = f"Admin/auth path /{path} [{code}]"
            elif code == 200 and path in ADMINISH:
                sev = "info"
                title = f"Path /{path} returned 200 (verify)"
            else:
                # do not create medium finding for every 403
                continue

            ctx.add_finding(
                title=title,
                severity=sev,
                category="Content Discovery",
                evidence=str(p),
                location=p.get("url") or "",
                remediation="Restrict sensitive paths; verify 200 responses are not soft-404 app shells.",
                source_tool=self.name,
            )

        ctx.artifacts["pages"] = len(pages)
        ctx.artifacts["paths"] = paths
        ctx.log_tool(self.name, "ok", f"pages={len(pages)} paths={len(paths)}")
        return ctx
