"""Tier C — manual VAPT checklist (not automated exploitation)."""

from .base import BaseTool
from ..context import PipelineContext

CHECKLIST = [
    "Business logic abuse (price, workflow, race)",
    "Complex authorization / IDOR across roles",
    "Multi-step / chained exploit scenarios",
    "SSO / OAuth / session fixation edge cases",
    "File upload → RCE / XSS chain (manual)",
    "Rate limiting / OTP / brute-force resistance",
    "Social engineering / phishing (out of pure app scan)",
    "Internal network pivot (only if scope allows)",
]


class TierCChecklistTool(BaseTool):
    name = "tier_c_manual"
    description = "Manual VAPT checklist for expert phase"
    order = 96

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        lines = "\n".join(f"[ ] {c}" for c in CHECKLIST)
        ctx.add_finding(
            title="Tier C — Manual VAPT checklist (expert)",
            severity="info",
            category="VAPT-Manual",
            evidence=lines,
            location=ctx.target,
            remediation="Complete these items under RoE; cannot be fully automated safely.",
            source_tool=self.name,
        )
        ctx.artifacts["tier_c_checklist"] = CHECKLIST
        ctx.log_tool(self.name, "ok", "checklist attached")
        return ctx
