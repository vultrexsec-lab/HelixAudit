"""
HelixAudit Scan Service — Pipeline-driven
Each tool receives accumulated context from previous tools.
"""

from datetime import datetime
from sqlalchemy.orm import Session
from ..models.models import Scan, Asset, Finding, ScanStatus, Severity
from ..pipeline.engine import PipelineEngine, default_tool_chain
from ..scanners.auth_scan import attempt_form_login, authenticated_crawl


def _sev(s: str) -> str:
    return {
        "critical": Severity.CRITICAL.value,
        "high": Severity.HIGH.value,
        "medium": Severity.MEDIUM.value,
        "low": Severity.LOW.value,
        "info": Severity.INFO.value,
    }.get((s or "info").lower(), Severity.INFO.value)


async def run_discovery_scan(db: Session, scan_id: int):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return

    try:
        scan.status = ScanStatus.RUNNING.value
        scan.started_at = datetime.utcnow()
        scan.progress = 3
        scan.error_message = None
        db.commit()

        def progress_cb(pct: int, tool_name: str):
            scan.progress = min(95, max(3, pct))
            db.commit()

        engine = PipelineEngine(default_tool_chain())
        ctx = await engine.run(scan.target.strip(), config=scan.config or {}, progress_cb=progress_cb)

        # Persist domains
        for d in ctx.domains:
            db.add(Asset(scan_id=scan.id, asset_type="subdomain", value=d, extra_data={"source": "pipeline"}))
        for p in ctx.ports:
            db.add(Asset(
                scan_id=scan.id, asset_type="port",
                value=f"{p.get('ip', '')}:{p.get('port')}",
                extra_data=p,
            ))
        for url in ctx.urls[:100]:
            db.add(Asset(scan_id=scan.id, asset_type="url", value=url, extra_data={}))
        if ctx.technologies:
            db.add(Asset(
                scan_id=scan.id, asset_type="technology",
                value=scan.target,
                extra_data={"technologies": ctx.technologies, "headers": ctx.headers},
            ))
        for page in ctx.pages[:50]:
            if page.get("url"):
                db.add(Asset(scan_id=scan.id, asset_type="page", value=page.get("url"), extra_data=page))
        for path in ctx.paths[:50]:
            if path.get("url"):
                db.add(Asset(scan_id=scan.id, asset_type="path", value=path.get("url"), extra_data=path))

        # Pipeline findings
        for f in ctx.findings:
            db.add(Finding(
                scan_id=scan.id,
                title=f.title,
                description=f"[{f.source_tool}] {f.title}",
                severity=_sev(f.severity),
                category=f.category,
                evidence=f.evidence,
                location=f.location,
                remediation=f.remediation,
                extra_data={"source_tool": f.source_tool},
            ))

        # Tool execution log as info findings summary
        ok = sum(1 for t in ctx.tool_logs if t.get("status") == "ok")
        err = sum(1 for t in ctx.tool_logs if t.get("status") == "error")
        db.add(Finding(
            scan_id=scan.id,
            title=f"Pipeline complete: {ok} tools ok, {err} errors",
            description="Tool chain finished",
            severity=Severity.INFO.value,
            category="Pipeline",
            evidence=str(ctx.to_summary()),
            location=scan.target,
            remediation="Review tool_logs in evidence for per-tool status.",
            extra_data={"tool_logs": ctx.tool_logs},
        ))
        db.commit()

        # Optional authenticated stage (uses credentials from config)
        config = scan.config or {}
        if config.get("username") and config.get("password"):
            scan.progress = 92
            db.commit()
            auth_client, auth_info = await attempt_form_login(
                scan.target, config["username"], config["password"], config.get("login_url")
            )
            db.add(Finding(
                scan_id=scan.id,
                title="Authenticated stage attempted",
                description=auth_info.get("message", ""),
                severity=Severity.INFO.value,
                category="Authenticated Scanning",
                evidence=str(auth_info),
                location=auth_info.get("login_url") or scan.target,
                remediation="Verify authz on authenticated resources.",
            ))
            if auth_client:
                try:
                    if auth_info.get("success"):
                        for ap in await authenticated_crawl(auth_client, scan.target):
                            db.add(Asset(scan_id=scan.id, asset_type="auth_page", value=ap.get("url"), extra_data=ap))
                    await auth_client.aclose()
                except Exception:
                    try:
                        await auth_client.aclose()
                    except Exception:
                        pass
            db.commit()

        # Clear password
        try:
            if scan.config and "password" in (scan.config or {}):
                cfg = dict(scan.config)
                cfg["password"] = "***cleared***"
                scan.config = cfg
        except Exception:
            pass

        scan.status = ScanStatus.COMPLETED.value
        scan.progress = 100
        scan.completed_at = datetime.utcnow()
        db.commit()

    except Exception as e:
        scan.status = ScanStatus.FAILED.value
        scan.error_message = str(e)[:500]
        scan.completed_at = datetime.utcnow()
        db.commit()
