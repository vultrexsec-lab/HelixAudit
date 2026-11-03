from .base import BaseTool
from ..context import PipelineContext
from ...scanners.techdetect import detect_technologies


class TechTool(BaseTool):
    name = "tech_detect"
    description = "Technology fingerprinting"
    order = 30

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        # Prefer first known URL else target
        url = ctx.urls[0] if ctx.urls else ctx.target
        tech = await detect_technologies(url)
        techs = tech.get("technologies") or []
        ctx.technologies = sorted(set(ctx.technologies + techs))
        if tech.get("headers"):
            ctx.headers.update({k.lower(): v for k, v in tech["headers"].items()})
        if tech.get("final_url"):
            ctx.merge_urls([tech["final_url"]])
        if techs:
            ctx.add_finding(
                title="Technologies detected",
                severity="info",
                category="Technology Fingerprint",
                evidence=", ".join(techs),
                location=tech.get("final_url") or url,
                remediation="Keep components updated; reduce version disclosure.",
                source_tool=self.name,
            )
        ctx.artifacts["tech"] = tech
        return ctx
