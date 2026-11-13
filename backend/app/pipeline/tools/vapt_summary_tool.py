"""Final VAPT-oriented summary of pipeline coverage."""

from .base import BaseTool
from ..context import PipelineContext


class VaptSummaryTool(BaseTool):
    name = "vapt_summary"
    description = "VAPT phase coverage summary"
    order = 95

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        phases = {
            "Reconnaissance": 0,
            "Enumeration": 0,
            "Vulnerability Assessment": 0,
            "Configuration": 0,
            "Authenticated": 0,
            "Other": 0,
        }
        for f in ctx.findings:
            cat = (f.category or "").lower()
            if "recon" in cat or "technology" in cat or "waf" in cat:
                phases["Reconnaissance"] += 1
            elif "enumer" in cat or "content" in cat or "sitemap" in cat or "api discovery" in cat:
                phases["Enumeration"] += 1
            elif "injection" in cat or "nuclei" in cat or "vulnerability" in cat or "access control" in cat:
                phases["Vulnerability Assessment"] += 1
            elif "misconfig" in cat or "ssl" in cat or "email" in cat or "configuration" in cat or "baseline" in cat:
                phases["Configuration"] += 1
            elif "auth" in cat:
                phases["Authenticated"] += 1
            else:
                phases["Other"] += 1

        tools_ok = [t for t in ctx.tool_logs if t.get("status") == "ok"]
        tools_err = [t for t in ctx.tool_logs if t.get("status") == "error"]
        tools_skip = [t for t in ctx.tool_logs if t.get("status") == "skipped"]

        evidence = (
            f"Phase counts: {phases}\n"
            f"Tools OK: {len(tools_ok)}, errors: {len(tools_err)}, skipped: {len(tools_skip)}\n"
            f"Domains: {len(ctx.domains)}, URLs: {len(ctx.urls)}, ports: {len(ctx.ports)}\n"
            f"Note: Automated VAPT-assist only. Manual verification required for full VAPT sign-off."
        )
        ctx.add_finding(
            title="VAPT coverage summary (automated)",
            severity="info",
            category="VAPT-Summary",
            evidence=evidence,
            location=ctx.target,
            remediation="Use this as baseline; complete manual tests per RoE/scope.",
            source_tool=self.name,
        )
        ctx.artifacts["vapt_phases"] = phases
        ctx.log_tool(self.name, "ok", "summary written")
        return ctx
