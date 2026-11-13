"""
HelixAudit Scan Service — Pipeline-driven with safe DB sessions.
"""

from datetime import datetime
from ..core.database import SessionLocal
from ..models.models import Scan, Asset, Finding, ScanStatus, Severity
from ..pipeline.engine import PipelineEngine, default_tool_chain
from .finding_quality import mask_secrets, dedupe_findings, risk_score, build_executive_summary
from .notify import send_scan_complete_email, email_configured
from .vapt_matrix import build_check_matrix, matrix_summary, chapter_findings
from ..scanners.auth_scan import attempt_form_login, authenticated_crawl, auth_findings_from_pages


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
                extra_data={"source_tool": f.get("source_tool"), "risk_score": score, "exposure": "public"},
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


        # VAPT coverage matrix (Pass/Fail/Not-tested)
        try:
            raw_for_matrix = []
            for f in cleaned:
                raw_for_matrix.append(f)
            # include pipeline summary already in DB? use cleaned + we'll add matrix after auth
            auth_configured = bool(config.get("username") and config.get("password"))
            matrix_rows = build_check_matrix(ctx.tool_logs, raw_for_matrix, auth_configured=auth_configured)
            # auth row updated after auth stage; preliminary matrix stored
            summary = matrix_summary(matrix_rows)
            db.add(Finding(
                scan_id=scan.id,
                title="VAPT coverage matrix (Pass/Fail/Not-tested)",
                description=f"pass={summary.get('pass')} fail={summary.get('fail')} not_tested={summary.get('not_tested')} error={summary.get('error')}",
                severity=Severity.INFO.value,
                category="VAPT-Coverage-Matrix",
                evidence=str(matrix_rows)[:15000],
                location=target,
                remediation="Expand not_tested checks (install tools, provide auth credentials).",
                extra_data={"type": "coverage_matrix", "summary": summary, "matrix": matrix_rows},
            ))
            db.commit()
        except Exception as me:
            print("matrix error:", me)

        # Optional authenticated deep stage (Phase A)
        if config.get("username") and config.get("password"):
            scan.progress = 94
            db.commit()
            try:
                auth_client, auth_info = await attempt_form_login(
                    target, config["username"], config["password"], config.get("login_url")
                )
                auth_pages = []
                if auth_client:
                    try:
                        auth_pages = await authenticated_crawl(auth_client, target, max_pages=25)
                        for ap in auth_pages:
                            db.add(Asset(
                                scan_id=scan.id,
                                asset_type="auth_page",
                                value=ap.get("url") or "",
                                extra_data={**(ap or {}), "exposure": "auth"},
                            ))
                        await auth_client.aclose()
                    except Exception:
                        try:
                            await auth_client.aclose()
                        except Exception:
                            pass

                for af in auth_findings_from_pages(auth_pages, auth_info):
                    score = risk_score(af.get("severity"), af.get("category"), af.get("location"))
                    db.add(Finding(
                        scan_id=scan.id,
                        title=(af.get("title") or "Auth finding")[:500],
                        description=(af.get("title") or "")[:1000],
                        severity=_sev(af.get("severity")),
                        category=(af.get("category") or "Authenticated Scanning")[:100],
                        evidence=mask_secrets((af.get("evidence") or "")[:5000]),
                        location=(af.get("location") or target)[:1000],
                        remediation=(af.get("remediation") or "")[:2000],
                        extra_data={
                            "source_tool": "auth_deep_scan",
                            "risk_score": score,
                            "exposure": af.get("exposure") or "auth",
                        },
                    ))
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

        # Phase B: email notify (optional SMTP)
        try:
            from ..models.models import Project
            proj = db.query(Project).filter(Project.id == scan.project_id).first()
            all_f = db.query(Finding).filter(Finding.scan_id == scan.id).all()
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in all_f:
                if f.severity in counts:
                    counts[f.severity] += 1
            if email_configured():
                result = send_scan_complete_email(
                    to_email=None,
                    project_name=proj.name if proj else "Project",
                    scan_id=scan.id,
                    target=scan.target,
                    status=scan.status,
                    counts=counts,
                    report_hint=f"HTML/PDF: /api/v1/scans/{scan.id}/report and /report.pdf",
                )
                print(f"[scan {scan_id}] email:", result)
        except Exception as ne:
            print("notify error:", ne)


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
