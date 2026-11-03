"""
HelixAudit Pipeline Engine
Runs tools in order; each tool receives full context from previous tools.
"""

from typing import List, Type
from .context import PipelineContext
from .tools.base import BaseTool


class PipelineEngine:
    def __init__(self, tools: List[BaseTool] | None = None):
        self.tools = sorted(tools or [], key=lambda t: t.order)

    def register(self, tool: BaseTool):
        self.tools.append(tool)
        self.tools.sort(key=lambda t: t.order)

    async def run(self, target: str, config: dict | None = None, progress_cb=None) -> PipelineContext:
        ctx = PipelineContext(target=target, config=config or {})
        total = max(len(self.tools), 1)

        for i, tool in enumerate(self.tools):
            if progress_cb:
                # 5% reserved start/end
                pct = 5 + int((i / total) * 90)
                try:
                    progress_cb(pct, tool.name)
                except Exception:
                    pass
            try:
                ctx = await tool.run(ctx)
                ctx.log_tool(tool.name, "ok", f"Completed {tool.name}")
            except Exception as e:
                ctx.log_tool(tool.name, "error", str(e)[:300])
                # continue chain — one tool failure must not kill pipeline

        if progress_cb:
            try:
                progress_cb(98, "aggregate")
            except Exception:
                pass
        return ctx


def default_tool_chain() -> List[BaseTool]:
    """Ordered open-source-style tool chain (extensible)."""
    from .tools import (
        subdomain_tool,
        port_tool,
        tech_tool,
        crawl_tool,
        secrets_tool,
        owasp_tool,
        active_tool,
        injection_tool,
    )
    return [
        subdomain_tool.SubdomainTool(),
        port_tool.PortTool(),
        tech_tool.TechTool(),
        crawl_tool.CrawlTool(),
        secrets_tool.SecretsTool(),
        owasp_tool.OwaspTool(),
        active_tool.ActiveTool(),
        injection_tool.InjectionTool(),
    ]
