"""Nuclei scanner with customizable templates, tags, and severity."""

import asyncio
import json
import subprocess
import tempfile
import os
from pathlib import Path
from .base import BaseTool
from ..context import PipelineContext
from ..binary import find_binary
from ...core.config import settings

# backend/nuclei-templates
_DEFAULT_CUSTOM_DIR = Path(__file__).resolve().parents[2] / "nuclei-templates"


class NucleiTool(BaseTool):
    name = "nuclei"
    description = "Nuclei template scan (custom + default templates)"
    order = 85

    def _cfg(self, ctx: PipelineContext, key: str, env_default: str = "") -> str:
        conf = ctx.config or {}
        # scan config first
        if key in conf and conf[key] is not None and conf[key] != "":
            return str(conf[key])
        # settings / env
        attr = key.upper()
        if hasattr(settings, attr):
            val = getattr(settings, attr)
            if val is not None and str(val) != "":
                return str(val)
        return env_default

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        if str((ctx.config or {}).get("nuclei_enabled", True)).lower() in ("0", "false", "no"):
            ctx.log_tool(self.name, "skipped", "disabled by suite/config")
            return ctx

        binary = find_binary("nuclei")
        if not binary:
            ctx.log_tool(self.name, "skipped", "nuclei binary not found — run scripts/install_tools.sh")
            return ctx

        urls = list(dict.fromkeys(ctx.urls[:15] if ctx.urls else [ctx.target]))
        if not urls:
            urls = [ctx.target]

        severity = self._cfg(ctx, "nuclei_severity", getattr(settings, "NUCLEI_SEVERITY", "critical,high,medium"))
        tags = self._cfg(ctx, "nuclei_tags", getattr(settings, "NUCLEI_TAGS", "") or "")
        exclude = self._cfg(ctx, "nuclei_exclude_tags", getattr(settings, "NUCLEI_EXCLUDE_TAGS", "dos,fuzz") or "dos,fuzz")
        rate = self._cfg(ctx, "nuclei_rate_limit", str(getattr(settings, "NUCLEI_RATE_LIMIT", 40)))
        req_timeout = self._cfg(ctx, "nuclei_timeout", str(getattr(settings, "NUCLEI_TIMEOUT", 5)))
        use_default = self._cfg(ctx, "nuclei_use_default", str(getattr(settings, "NUCLEI_USE_DEFAULT", True))).lower() in (
            "1", "true", "yes", ""
        )

        template_path = self._cfg(ctx, "nuclei_template_path", getattr(settings, "NUCLEI_TEMPLATE_PATH", "") or "")
        if not template_path:
            template_path = str(_DEFAULT_CUSTOM_DIR)

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            list_path = f.name

        try:
            def _run():
                cmd = [
                    binary,
                    "-l", list_path,
                    "-severity", severity,
                    "-silent",
                    "-jsonl",
                    "-timeout", str(req_timeout),
                    "-retries", "0",
                    "-rate-limit", str(rate),
                    "-c", "10",
                    "-max-host-error", "3",
                ]
                # Custom templates directory
                if template_path and Path(template_path).exists():
                    cmd.extend(["-t", template_path])
                # Default nuclei templates (if installed via -ut)
                if use_default:
                    # nuclei uses default template dir automatically when -t not exclusive;
                    # when -t is set it may only use that path — add both if default exists
                    home_tpl = Path.home() / "nuclei-templates"
                    if home_tpl.exists() and str(home_tpl.resolve()) != str(Path(template_path).resolve()):
                        cmd.extend(["-t", str(home_tpl)])

                if tags:
                    cmd.extend(["-tags", tags])
                if exclude:
                    cmd.extend(["-exclude-tags", exclude])

                return subprocess.run(cmd, capture_output=True, text=True, timeout=100)

            try:
                proc = await asyncio.to_thread(_run)
            except subprocess.TimeoutExpired:
                ctx.log_tool(self.name, "error", "nuclei timed out after 100s")
                ctx.add_finding(
                    title="Nuclei scan timed out",
                    severity="info",
                    category="Nuclei",
                    evidence="Process exceeded 100s limit",
                    location=ctx.target,
                    remediation="Reduce severity/tags or target count.",
                    source_tool=self.name,
                )
                return ctx
            except Exception as e:
                ctx.log_tool(self.name, "error", str(e)[:200])
                return ctx

            stderr_tail = (proc.stderr or "")[-400:]
            hits = 0
            for line in (proc.stdout or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                hits += 1
                info = obj.get("info") or {}
                name = info.get("name") or obj.get("template-id") or "Nuclei match"
                sev = (info.get("severity") or "medium").lower()
                matched = obj.get("matched-at") or obj.get("host") or ctx.target
                template_id = obj.get("template-id") or obj.get("templateID") or ""
                ctx.add_finding(
                    title=f"[Nuclei] {name}",
                    severity=sev if sev in ["critical", "high", "medium", "low", "info"] else "medium",
                    category="Nuclei Template",
                    evidence=f"template={template_id} {str(obj)[:700]}",
                    location=str(matched)[:500],
                    remediation=(info.get("description") or "Review nuclei finding and apply vendor guidance.")[:500],
                    source_tool=self.name,
                )

            ctx.artifacts["nuclei"] = {
                "hits": hits,
                "severity": severity,
                "tags": tags,
                "exclude_tags": exclude,
                "template_path": template_path,
                "use_default": use_default,
                "stderr_tail": stderr_tail,
            }

            if hits == 0:
                ctx.add_finding(
                    title="Nuclei completed — no matches for selected templates/severity",
                    severity="info",
                    category="Nuclei",
                    evidence=(
                        f"targets={len(urls)} severity={severity} tags={tags or '-'} "
                        f"exclude={exclude} templates={template_path}"
                    ),
                    location=ctx.target,
                    remediation="Customize nuclei-templates/ or NUCLEI_TAGS / NUCLEI_SEVERITY.",
                    source_tool=self.name,
                )
            ctx.log_tool(self.name, "ok", f"hits={hits} severity={severity}")
        finally:
            try:
                os.unlink(list_path)
            except Exception:
                pass
        return ctx
