"""
HelixAudit Pipeline Engine
Runs tools in order with per-tool timeouts so one tool cannot hang the scan.
"""

import asyncio
from typing import List
from .context import PipelineContext
from .tools.base import BaseTool

# Max seconds per tool — prevents stuck at 78% style hangs
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

            # Longer timeout for nuclei / httpx / subfinder
            timeout = self.tool_timeout
            if tool.name in ("nuclei", "httpx_probe", "subfinder", "crawler"):
                timeout = 90
            if tool.name in ("injection_detect", "active_checks"):
                timeout = 40

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
                    evidence=f"{tool.name} exceeded {timeout}s and was skipped",
                    location=ctx.target,
                    remediation="Retry later or reduce target scope.",
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
        port_tool,
        httpx_tool,
        tech_tool,
        crawl_tool,
        secrets_tool,
        owasp_tool,
        active_tool,
        injection_tool,
        nuclei_tool,
    )
    return [
        subfinder_tool.SubfinderTool(),
        subdomain_tool.SubdomainTool(),
        port_tool.PortTool(),
        httpx_tool.HttpxTool(),
        tech_tool.TechTool(),
        crawl_tool.CrawlTool(),
        secrets_tool.SecretsTool(),
        owasp_tool.OwaspTool(),
        active_tool.ActiveTool(),
        injection_tool.InjectionTool(),
        nuclei_tool.NucleiTool(),
    ]
