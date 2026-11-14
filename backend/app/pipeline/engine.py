"""
HelixAudit Pipeline Engine — VAPT Tier A/B + manual Tier C checklist.
"""

import asyncio
from typing import List
from .context import PipelineContext
from .tools.base import BaseTool
from .suites import filter_tools, apply_suite_to_config

DEFAULT_TOOL_TIMEOUT = 45


class PipelineEngine:
    def __init__(self, tools: List[BaseTool] | None = None, tool_timeout: int = DEFAULT_TOOL_TIMEOUT):
        self.tools = sorted(tools or [], key=lambda t: t.order)
        self.tool_timeout = tool_timeout

    def register(self, tool: BaseTool):
        self.tools.append(tool)
        self.tools.sort(key=lambda t: t.order)

    async def run(self, target: str, config: dict | None = None, progress_cb=None) -> PipelineContext:
        config = apply_suite_to_config(config or {}, (config or {}).get("suite"))
        tools = filter_tools(self.tools, config.get("suite"))
        ctx = PipelineContext(target=target, config=config)
        total = max(len(tools), 1)

        for i, tool in enumerate(tools):
            if progress_cb:
                pct = 5 + int((i / total) * 90)
                try:
                    progress_cb(pct, tool.name)
                except Exception:
                    pass

            timeout = self.tool_timeout
            if tool.name in ("nuclei", "httpx_probe", "subfinder", "crawler", "dir_brute", "js_endpoints"):
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
    from .tools import (
        subfinder_tool,
        subdomain_tool,
        dns_email_tool,
        port_tool,
        live_probe_tool,
        waf_detect_tool,
        ssl_tool,
        https_redirect_tool,
        tech_tool,
        cookie_tool,
        crawl_tool,
        sitemap_tool,
        dir_brute_tool,
        api_discover_tool,
        swagger_tool,
        js_endpoints_tool,
        headers_baseline_tool,
        vuln_paths_tool,
        upload_surface_tool,
        secrets_tool,
        owasp_tool,
        active_tool,
        injection_tool,
        nuclei_tool,
        vapt_summary_tool,
        tier_c_checklist_tool,
    )
    return [
        # Tier A — Recon
        subfinder_tool.SubfinderTool(),
        subdomain_tool.SubdomainTool(),
        dns_email_tool.DnsEmailTool(),
        port_tool.PortTool(),
        live_probe_tool.LiveProbeTool(),
        waf_detect_tool.WafDetectTool(),
        # Tier A — Config
        ssl_tool.SslTool(),
        https_redirect_tool.HttpsRedirectTool(),
        tech_tool.TechTool(),
        cookie_tool.CookieTool(),
        # Tier A/B — Enumeration
        crawl_tool.CrawlTool(),
        sitemap_tool.SitemapTool(),
        dir_brute_tool.DirBruteTool(),
        api_discover_tool.ApiDiscoverTool(),
        swagger_tool.SwaggerTool(),
        js_endpoints_tool.JsEndpointsTool(),
        headers_baseline_tool.HeadersBaselineTool(),
        vuln_paths_tool.VulnPathsTool(),
        upload_surface_tool.UploadSurfaceTool(),
        # Tier A — VA
        secrets_tool.SecretsTool(),
        owasp_tool.OwaspTool(),
        active_tool.ActiveTool(),
        injection_tool.InjectionTool(),
        nuclei_tool.NucleiTool(),
        # Summary + Tier C manual checklist
        vapt_summary_tool.VaptSummaryTool(),
        tier_c_checklist_tool.TierCChecklistTool(),
    ]
