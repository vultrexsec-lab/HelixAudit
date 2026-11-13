from .base import BaseTool
from ..context import PipelineContext
from ...scanners.crawler import crawl_site, directory_discovery
import httpx
from ...scanners.soft404 import is_soft404, real_sensitive_content, body_hash
from urllib.parse import urlparse

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
        ctx.paths.extend(paths)
        ctx.merge_urls([p.get("url") for p in paths if p.get("url")])

        parsed = urlparse(target if "://" in target else f"https://{target}")
        origin = f"{parsed.scheme}://{parsed.netloc}"
        baseline = set()
        headers = {"User-Agent": "HelixAudit-Pipeline/1.6.3"}

        async with httpx.AsyncClient(follow_redirects=False, timeout=8.0, verify=False, headers=headers) as client:
            try:
                home = await client.get(origin + "/")
                baseline.add(body_hash(home.content))
            except Exception:
                pass
            try:
                rnd = await client.get(origin + "/helixaudit-soft404-crawl-888")
                if rnd.status_code == 200:
                    baseline.add(body_hash(rnd.content))
            except Exception:
                pass

            for p in paths:
                path = (p.get("path") or "").strip("/")
                code = p.get("status_code")
                url = p.get("url") or (origin + "/" + path)
                if code != 200:
                    continue
                if path not in SENSITIVE and path not in ADMINISH:
                    continue
                try:
                    r = await client.get(url)
                    text = r.text or ""
                    ct = r.headers.get("content-type", "")
                    if is_soft404(r.content, ct, baseline, text) and not real_sensitive_content(path, r.content, text):
                        continue
                    if path in SENSITIVE:
                        if real_sensitive_content(path, r.content, text):
                            sev, title = "high", f"Confirmed sensitive content: /{path}"
                        else:
                            # non-html 200 without signatures — low
                            if is_soft404(r.content, ct, baseline, text):
                                continue
                            sev, title = "info", f"Sensitive path 200 unverified: /{path}"
                    else:
                        sev, title = "info", f"Admin/auth path 200 (verify): /{path}"
                    ctx.add_finding(
                        title=title,
                        severity=sev,
                        category="Content Discovery",
                        evidence=f"status={r.status_code} length={len(r.content)} ct={ct}",
                        location=url,
                        remediation="Confirm manually; SPA soft-404 is not an exposure.",
                        source_tool=self.name,
                    )
                except Exception:
                    continue

        ctx.artifacts["pages"] = len(pages)
        ctx.artifacts["paths"] = paths
        ctx.log_tool(self.name, "ok", f"pages={len(pages)} paths={len(paths)}")
        return ctx
