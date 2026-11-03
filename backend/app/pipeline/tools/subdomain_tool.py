from .base import BaseTool
from ..context import PipelineContext
from ...scanners.subdomain import enumerate_subdomains


class SubdomainTool(BaseTool):
    name = "subdomain_enum"
    description = "Subdomain enumeration"
    order = 10

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        subs = await enumerate_subdomains(ctx.target)
        ctx.domains = sorted(set(ctx.domains + subs))
        for s in subs:
            ctx.merge_urls([f"https://{s}"])
        ctx.artifacts["subdomains"] = subs
        return ctx
