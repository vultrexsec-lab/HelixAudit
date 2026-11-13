"""
HelixAudit Scan Service — Pipeline-driven with safe DB sessions.
"""

from datetime import datetime
from ..core.database import SessionLocal
from ..models.models import Scan, Asset, Finding, ScanStatus, Severity
from ..pipeline.engine import PipelineEngine, default_tool_chain
from .finding_quality import mask_secrets, dedupe_findings, risk_score, build_executive_summary
from ..scanners.auth_scan import attempt_form_login, authenticated_crawl


def _sev(s: str) -> str:
    return {
        "critical": Severity.CRITICAL.value,
        "high": Severity.HIGH.value,
        "medium": Severity.MEDIUM.value,
        "low": Severity.LOW.value,
        "info": Severity.INFO.value,
    }.get((s or "info").lower(), Severity.INFO.value)


def _set_progress(scan_id: int, progress: int, status: str | None = None):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        scan.progress = min(99, max(0, progress))
        if status:
            scan.status = status
        db.commit()
    except Exception as e:
        print("progress update error:", e)
        db.rollback()
    finally:
        db.close()


async def run_discovery_scan(scan_id: int):
    """Background-safe: opens its own DB session. Do NOT pass request session."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        scan.status = ScanStatus.RUNNING.value
        scan.started_at = datetime.utcnow()
        scan.progress = 3
        scan.error_message = None
        db.commit()

        target = (scan.target or "").strip()
        config = dict(scan.config or {})
        db.close()  # release before long-running pipeline
        db = None

        def progress_cb(pct: int, tool_name: str):
            print(f"[scan {scan_id}] {pct}% — {tool_name}")
            _set_progress(scan_id, pct, ScanStatus.RUNNING.value)

        engine = PipelineEngine(default_tool_chain())
        try:
            ctx = await engine.run(target, config=config, progress_cb=progress_cb)
        except Exception as e:
            print(f"[scan {scan_id}] pipeline error:", e)
            db = SessionLocal()
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.FAILED.value
                scan.error_message = f"Pipeline error: {str(e)[:400]}"
                scan.completed_at = datetime.utcnow()
                scan.progress = 100
                db.commit()
            db.close()
            return

        # Persist results with a fresh session
        db = SessionLocal()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            db.close()
            return

        scan.progress = 90
        db.commit()

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
                value=target,
                extra_data={"technologies": ctx.technologies, "headers": ctx.headers},
            ))
        for page in ctx.pages[:50]:
            if page.get("url"):
                db.add(Asset(scan_id=scan.id, asset_type="page", value=page.get("url"), extra_data=page))
        for path in ctx.paths[:50]:
            if path.get("url"):
                db.add(Asset(scan_id=scan.id, asset_type="path", value=path.get("url"), extra_data=path))

        raw = []
        for f in ctx.findings:
            raw.append({
                "title": f.title[:500] if f.title else "Finding",
                "description": f"[{f.source_tool}] {f.title}"[:1000],
                "severity": _sev(f.severity),
                "category": (f.category or "general")[:100],
                "evidence": mask_secrets((f.evidence or "")[:5000]),
                "location": (f.location or "")[:1000],
                "remediation": (f.remediation or "")[:2000],
                "source_tool": f.source_tool,
            })
        cleaned = dedupe_findings(raw)
        for f in cleaned:
            score = risk_score(f.get("severity"), f.get("category"), f.get("location"))
            db.add(Finding(
                scan_id=scan.id,
                title=f["title"],
                description=f.get("description"),
                severity=f.get("severity") or "info",
                category=f.get("category"),
                evidence=f.get("evidence"),
                location=f.get("location"),
                remediation=f.get("remediation"),
                extra_data={"source_tool": f.get("source_tool"), "risk_score": score},
            ))
        # Executive summary finding
        exec_sum = build_executive_summary(target, cleaned, len(ctx.urls) + len(ctx.domains))
        db.add(Finding(
            scan_id=scan.id,
            title="Executive Summary",
            description=exec_sum[:2000],
            severity="info",
            category="Executive Summary",
            evidence=exec_sum[:5000],
            location=target,
            remediation="Share executive summary with stakeholders; track Critical/High to closure.",
            extra_data={"risk_score": 0, "type": "executive_summary"},
        ))

        ok = sum(1 for t in ctx.tool_logs if t.get("status") == "ok")
        err = sum(1 for t in ctx.tool_logs if t.get("status") == "error")
        skipped = sum(1 for t in ctx.tool_logs if t.get("status") == "skipped")
        db.add(Finding(
            scan_id=scan.id,
            title=f"Pipeline complete: {ok} ok, {skipped} skipped, {err} errors",
            description="Tool chain finished",
            severity=Severity.INFO.value,
            category="Pipeline",
            evidence=str(ctx.to_summary())[:5000],
            location=target,
            remediation="Review tool_logs in evidence for per-tool status.",
            extra_data={"tool_logs": ctx.tool_logs},
        ))
        db.commit()

        # Optional authenticated stage
        if config.get("username") and config.get("password"):
            scan.progress = 94
            db.commit()
            try:
                auth_client, auth_info = await attempt_form_login(
                    target, config["username"], config["password"], config.get("login_url")
                )
                db.add(Finding(
                    scan_id=scan.id,
                    title="Authenticated stage attempted",
                    description=(auth_info.get("message") or "")[:500],
                    severity=Severity.INFO.value,
                    category="Authenticated Scanning",
                    evidence=str(auth_info)[:3000],
                    location=auth_info.get("login_url") or target,
                    remediation="Verify authorization on authenticated resources.",
                ))
                if auth_client:
                    try:
                        if auth_info.get("success"):
                            for ap in await authenticated_crawl(auth_client, target):
                                db.add(Asset(
                                    scan_id=scan.id,
                                    asset_type="auth_page",
                                    value=ap.get("url") or "",
                                    extra_data=ap,
                                ))
                        await auth_client.aclose()
                    except Exception:
                        try:
                            await auth_client.aclose()
                        except Exception:
                            pass
                db.commit()
            except Exception as e:
                print("auth stage error:", e)

        # Clear password from stored config
        try:
            if scan.config and isinstance(scan.config, dict) and "password" in scan.config:
                cfg = dict(scan.config)
                cfg["password"] = "***cleared***"
                scan.config = cfg
        except Exception:
            pass

        scan.status = ScanStatus.COMPLETED.value
        scan.progress = 100
        scan.completed_at = datetime.utcnow()
        db.commit()
        print(f"[scan {scan_id}] COMPLETED findings={len(ctx.findings)} urls={len(ctx.urls)}")

    except Exception as e:
        print(f"[scan {scan_id}] FATAL:", e)
        try:
            if db:
                db.rollback()
                db.close()
        except Exception:
            pass
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.FAILED.value
                scan.error_message = str(e)[:500]
                scan.completed_at = datetime.utcnow()
                scan.progress = 100
                db.commit()
        finally:
            db.close()
    finally:
        try:
            if db:
                db.close()
        except Exception:
            pass
