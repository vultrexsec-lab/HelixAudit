"""
HelixAudit Pipeline Engine — VAPT-oriented sequential tool chain.
"""

import asyncio
from typing import List
from .context import PipelineContext
from .tools.base import BaseTool

DEFAULT_TOOL_TIMEOUT = 45


class PipelineEngine:
    def __init__(self, tools: List[BaseTool] | None = None, tool_timeout: int = DEFAULT_TOOL_TIMEOUT):
        self.tools = sorted(tools or [], key=lambda t: t.order)
        self.tool_timeout = tool_timeout

    def register(self, tool: BaseTool):
        self.tools.append(tool)
        self.tools.sort(key=lambda t: t.order)

    async def run(self, target: str, config: dict | None = None, progress_cb=None) -> PipelineContext:
        ctx = PipelineContext(target=target, config=config or {})
        total = max(len(self.tools), 1)

        for i, tool in enumerate(self.tools):
            if progress_cb:
                pct = 5 + int((i / total) * 90)
                try:
                    progress_cb(pct, tool.name)
                except Exception:
                    pass

            timeout = self.tool_timeout
            if tool.name in ("nuclei", "httpx_probe", "subfinder", "crawler"):
                timeout = 90
            if tool.name in ("injection_detect", "active_checks", "vuln_paths"):
                timeout = 50

            try:
                ctx = await asyncio.wait_for(tool.run(ctx), timeout=timeout)
                if not any(l.get("tool") == tool.name for l in ctx.tool_logs):
                    ctx.log_tool(tool.name, "ok", f"Completed {tool.name}")
            except asyncio.TimeoutError:
                ctx.log_tool(tool.name, "error", f"Timed out after {timeout}s")
                ctx.add_finding(
                    title=f"Tool timed out: {tool.name}",
                    severity="info",
                    category="Pipeline",
                    evidence=f"{tool.name} exceeded {timeout}s",
                    location=ctx.target,
                    remediation="Retry or reduce scope.",
                    source_tool=tool.name,
                )
            except Exception as e:
                ctx.log_tool(tool.name, "error", str(e)[:300])

        if progress_cb:
            try:
                progress_cb(98, "aggregate")
            except Exception:
                pass
        return ctx


def default_tool_chain() -> List[BaseTool]:
    """Full automated VAPT-assist chain (authorized targets only)."""
    from .tools import (
        subfinder_tool,
        subdomain_tool,
        dns_email_tool,
        port_tool,
        httpx_tool,
        waf_detect_tool,
        ssl_tool,
        https_redirect_tool,
        tech_tool,
        crawl_tool,
        sitemap_tool,
        api_discover_tool,
        headers_baseline_tool,
        vuln_paths_tool,
        secrets_tool,
        owasp_tool,
        active_tool,
        injection_tool,
        nuclei_tool,
        vapt_summary_tool,
    )
    return [
        # Phase 1 — Recon
        subfinder_tool.SubfinderTool(),
        subdomain_tool.SubdomainTool(),
        dns_email_tool.DnsEmailTool(),
        port_tool.PortTool(),
        httpx_tool.HttpxTool(),
        waf_detect_tool.WafDetectTool(),
        # Phase 2 — Config / transport
        ssl_tool.SslTool(),
        https_redirect_tool.HttpsRedirectTool(),
        tech_tool.TechTool(),
        # Phase 3 — Enumeration
        crawl_tool.CrawlTool(),
        sitemap_tool.SitemapTool(),
        api_discover_tool.ApiDiscoverTool(),
        headers_baseline_tool.HeadersBaselineTool(),
        vuln_paths_tool.VulnPathsTool(),
        # Phase 4 — Vulnerability assessment (surface/detection)
        secrets_tool.SecretsTool(),
        owasp_tool.OwaspTool(),
        active_tool.ActiveTool(),
        injection_tool.InjectionTool(),
        nuclei_tool.NucleiTool(),
        # Phase 5 — Summary
        vapt_summary_tool.VaptSummaryTool(),
    ]
