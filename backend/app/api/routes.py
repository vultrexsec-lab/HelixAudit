from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel, HttpUrl
from datetime import datetime

from ..core.database import get_db, Base, engine
from ..models.models import Project, Scan, Asset, Finding, ScanStatus
from ..services.scan_service import run_discovery_scan

router = APIRouter()

# Create tables
Base.metadata.create_all(bind=engine)


# ---------- Pydantic Schemas ----------
class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None
    client_name: Optional[str] = None
    scope: Optional[str] = None


class ProjectOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
    client_name: Optional[str]
    scope: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class ScanCreate(BaseModel):
    project_id: int
    target: str
    scan_type: str = "discovery"
    suite: str = "standard"  # quick | standard | full | owasp | nuclei_top
    # Optional authenticated scan
    username: str | None = None
    password: str | None = None
    login_url: str | None = None


class ScanOut(BaseModel):
    id: int
    project_id: int
    target: str
    status: str
    scan_type: str
    progress: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class AssetOut(BaseModel):
    id: int
    asset_type: str
    value: str
    extra_data: Optional[dict]
    created_at: datetime

    class Config:
        from_attributes = True


class FindingOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: str
    category: Optional[str]
    evidence: Optional[str]
    location: Optional[str]
    remediation: Optional[str]
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


# ---------- Project Routes ----------
@router.post("/projects", response_model=ProjectOut)
def create_project(project: ProjectCreate, db: Session = Depends(get_db)):
    db_project = Project(**project.dict())
    db.add(db_project)
    db.commit()
    db.refresh(db_project)
    return db_project


@router.get("/projects", response_model=List[ProjectOut])
def list_projects(db: Session = Depends(get_db)):
    return db.query(Project).order_by(Project.created_at.desc()).all()


@router.get("/projects/{project_id}", response_model=ProjectOut)
def get_project(project_id: int, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


# ---------- Scan Routes ----------
@router.post("/scans", response_model=ScanOut)
def create_scan(scan: ScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == scan.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    config = {}
    if scan.username:
        config["username"] = scan.username
    if scan.password:
        config["password"] = scan.password  # note: sensitive; prefer ephemeral in production
    if scan.login_url:
        config["login_url"] = scan.login_url
    if getattr(scan, "suite", None):
        config["suite"] = scan.suite
    elif scan.scan_type in ("quick", "standard", "full", "owasp", "nuclei_top"):
        config["suite"] = scan.scan_type

    db_scan = Scan(
        project_id=scan.project_id,
        target=scan.target,
        scan_type=scan.scan_type,
        status=ScanStatus.PENDING.value,
        config=config or None,
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    
    # Start scan in background
    background_tasks.add_task(run_discovery_scan, db_scan.id)
    
    return db_scan


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/scans/{scan_id}/assets", response_model=List[AssetOut])
def get_scan_assets(scan_id: int, db: Session = Depends(get_db)):
    return db.query(Asset).filter(Asset.scan_id == scan_id).all()


@router.get("/scans/{scan_id}/findings", response_model=List[FindingOut])
def get_scan_findings(scan_id: int, db: Session = Depends(get_db)):
    return db.query(Finding).filter(Finding.scan_id == scan_id).order_by(Finding.created_at.desc()).all()


@router.get("/projects/{project_id}/scans", response_model=List[ScanOut])
def list_project_scans(project_id: int, db: Session = Depends(get_db)):
    return db.query(Scan).filter(Scan.project_id == project_id).order_by(Scan.created_at.desc()).all()



# ---------- Phase 5 + 8: Finding Lifecycle + Enhanced Reports ----------

class FindingStatusUpdate(BaseModel):
    status: str  # new, confirmed, false_positive, fixed, retest


@router.patch("/findings/{finding_id}", response_model=FindingOut)
def update_finding_status(finding_id: int, payload: FindingStatusUpdate, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    allowed = {"new", "confirmed", "false_positive", "fixed", "retest"}
    if payload.status not in allowed:
        raise HTTPException(status_code=400, detail=f"status must be one of {allowed}")
    finding.status = payload.status
    db.commit()
    db.refresh(finding)
    return finding


def _build_report_data(db: Session, scan_id: int):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return None
    project = db.query(Project).filter(Project.id == scan.project_id).first()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_sorted = sorted(findings, key=lambda f: severity_order.get(f.severity, 5))
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {
        "scan": scan,
        "project": project,
        "findings": findings_sorted,
        "assets": assets,
        "counts": counts,
    }


@router.get("/scans/{scan_id}/report")

def generate_report(scan_id: int, db: Session = Depends(get_db)):
    """Professional HTML VAPT report with coverage matrix + chapters."""
    from fastapi.responses import HTMLResponse
    from ..services.vapt_matrix import chapter_findings as group_chapters

    data = _build_report_data(db, scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan, project, findings, assets, counts = (
        data["scan"], data["project"], data["findings"], data["assets"], data["counts"]
    )

    def rows_for(items):
        rows = ""
        for f in items:
            evidence = (getattr(f, "evidence", None) or "")[:300].replace("<", "&lt;").replace(">", "&gt;")
            remediation = (getattr(f, "remediation", None) or "")[:250].replace("<", "&lt;").replace(">", "&gt;")
            title = (getattr(f, "title", None) or "").replace("<", "&lt;")
            loc = getattr(f, "location", None) or ""
            cat = getattr(f, "category", None) or ""
            sev = getattr(f, "severity", None) or "info"
            st = getattr(f, "status", None) or "new"
            rows += f"""
        <tr>
          <td><span class="sev {sev}">{sev.upper()}</span></td>
          <td>
            <strong>{title}</strong><br/>
            <small>{loc}</small>
            {f'<div class="ev">{evidence}</div>' if evidence else ''}
            {f'<div class="rem"><b>Remediation:</b> {remediation}</div>' if remediation else ''}
          </td>
          <td>{cat}</td>
          <td>{st}</td>
        </tr>"""
        return rows or '<tr><td colspan="4">No findings in this section</td></tr>'

    exec_findings = [f for f in findings if (f.category or "") == "Executive Summary"]
    matrix_finding = next((f for f in findings if (f.category or "") == "VAPT-Coverage-Matrix"), None)
    exec_html = ""
    if exec_findings:
        ex = (exec_findings[0].evidence or exec_findings[0].description or "").replace("<", "&lt;")
        exec_html = f'<pre style="white-space:pre-wrap;background:#f8fafc;padding:1rem;border-radius:8px;">{ex}</pre>'

    matrix_html = "<h2>VAPT coverage matrix</h2><p class='meta'>Matrix not generated for this scan (re-run scan on v1.7+).</p>"
    if matrix_finding and isinstance(matrix_finding.extra_data, dict):
        matrix = matrix_finding.extra_data.get("matrix") or []
        summary = matrix_finding.extra_data.get("summary") or {}
        mrows = ""
        for r in matrix:
            st = r.get("status") or ""
            mrows += (
                f"<tr><td>{r.get('chapter','')}</td><td>{r.get('name','')}</td>"
                f"<td><span class='st {st}'>{st}</span></td><td>{r.get('detail') or ''}</td></tr>"
            )
        matrix_html = f"""
  <h2>VAPT coverage matrix (Pass / Fail / Not-tested)</h2>
  <div class="summary">
    <div class="box"><strong>{summary.get("pass",0)}</strong>Pass</div>
    <div class="box"><strong>{summary.get("fail",0)}</strong>Fail</div>
    <div class="box"><strong>{summary.get("info_only",0)}</strong>Info</div>
    <div class="box"><strong>{summary.get("not_tested",0)}</strong>Not tested</div>
    <div class="box"><strong>{summary.get("error",0)}</strong>Error</div>
  </div>
  <table>
    <thead><tr><th>Chapter</th><th>Check</th><th>Status</th><th>Detail</th></tr></thead>
    <tbody>{mrows or '<tr><td colspan="4">No matrix</td></tr>'}</tbody>
  </table>
"""

    as_dicts = []
    for f in findings:
        as_dicts.append({
            "title": f.title, "severity": f.severity, "category": f.category,
            "location": f.location, "evidence": f.evidence, "remediation": f.remediation,
            "status": f.status, "extra_data": f.extra_data or {},
        })
    chapters = group_chapters(as_dicts)
    chapter_html = ""
    for ch_name in ["Reconnaissance", "Configuration", "Enumeration", "Vulnerability Assessment", "Authenticated Testing", "Other"]:
        items = chapters.get(ch_name) or []
        class FObj:
            pass
        flist = []
        for d in items:
            if d.get("category") in ("Executive Summary", "VAPT-Coverage-Matrix"):
                continue
            o = FObj()
            o.title = d.get("title")
            o.severity = d.get("severity")
            o.category = d.get("category")
            o.location = d.get("location")
            o.evidence = d.get("evidence")
            o.remediation = d.get("remediation")
            o.status = d.get("status")
            o.extra_data = d.get("extra_data") or {}
            flist.append(o)
        chapter_html += (
            f"<h2>{ch_name} ({len(flist)})</h2>"
            f"<table><thead><tr><th>Severity</th><th>Title / Evidence / Remediation</th>"
            f"<th>Category</th><th>Status</th></tr></thead>"
            f"<tbody>{rows_for(flist)}</tbody></table>"
        )

    asset_rows = "".join(
        f"<tr><td>{a.asset_type}</td><td>{(a.value or '')[:120]}</td></tr>"
        for a in assets[:100]
    )

    client = ""
    if project and getattr(project, "client_name", None):
        client = f"<div><strong>Prepared for:</strong> {project.client_name}</div>"

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>HelixAudit VAPT Report - Scan #{scan.id}</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; margin: 2rem; color: #0f172a; }}
  h1 {{ margin-bottom: 0.25rem; }}
  h2 {{ margin-top: 1.75rem; border-bottom: 1px solid #e2e8f0; padding-bottom: 0.35rem; }}
  .meta {{ color: #64748b; margin-bottom: 1.5rem; font-size: 0.95rem; }}
  .summary {{ display: flex; gap: 0.75rem; flex-wrap: wrap; margin: 1rem 0 1.5rem; }}
  .box {{ background: #f1f5f9; padding: 0.9rem 1.1rem; border-radius: 8px; min-width: 90px; text-align: center; }}
  .box strong {{ display: block; font-size: 1.4rem; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 0.75rem; font-size: 0.9rem; }}
  th, td {{ text-align: left; padding: 0.55rem 0.65rem; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
  th {{ background: #f8fafc; }}
  .sev {{ padding: 0.12rem 0.4rem; border-radius: 4px; font-size: 0.72rem; font-weight: 700; }}
  .critical {{ background: #fee2e2; color: #991b1b; }}
  .high {{ background: #ffedd5; color: #9a3412; }}
  .medium {{ background: #fef3c7; color: #92400e; }}
  .low {{ background: #dbeafe; color: #1e40af; }}
  .info {{ background: #f1f5f9; color: #475569; }}
  .st {{ padding: 0.12rem 0.4rem; border-radius: 4px; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; }}
  .st.pass {{ background: #dcfce7; color: #166534; }}
  .st.fail {{ background: #fee2e2; color: #991b1b; }}
  .st.not_tested {{ background: #e2e8f0; color: #475569; }}
  .st.error {{ background: #ffedd5; color: #9a3412; }}
  .st.info_only {{ background: #e0f2fe; color: #075985; }}
  .ev {{ color: #64748b; font-size: 0.82rem; margin-top: 0.25rem; }}
  .rem {{ color: #334155; font-size: 0.82rem; margin-top: 0.2rem; }}
  .footer {{ margin-top: 2rem; color: #94a3b8; font-size: 0.85rem; }}
  .actions button {{ margin: 0.5rem 0 1rem; padding: 0.5rem 1rem; }}
</style>
</head>
<body>
  <h1>HelixAudit — VAPT Assessment Report</h1>
  <div class="meta">
    {client}
    <div><strong>Project:</strong> {project.name if project else 'N/A'}</div>
    <div><strong>Target:</strong> {scan.target}</div>
    <div><strong>Scan ID:</strong> #{scan.id} &nbsp;|&nbsp; <strong>Status:</strong> {scan.status}</div>
    <div><strong>Window:</strong> {scan.started_at} → {scan.completed_at}</div>
  </div>
  <div class="actions"><button onclick="window.print()">Print / Save as PDF</button></div>

  <h2>1. Executive Summary</h2>
  <div class="summary">
    <div class="box"><strong>{counts['critical']}</strong>Critical</div>
    <div class="box"><strong>{counts['high']}</strong>High</div>
    <div class="box"><strong>{counts['medium']}</strong>Medium</div>
    <div class="box"><strong>{counts['low']}</strong>Low</div>
    <div class="box"><strong>{counts['info']}</strong>Info</div>
    <div class="box"><strong>{len(assets)}</strong>Assets</div>
  </div>
  {exec_html}

  {matrix_html}

  <h2>3. Findings by VAPT chapter</h2>
  {chapter_html}

  <h2>4. Discovered Assets (sample)</h2>
  <table>
    <thead><tr><th>Type</th><th>Value</th></tr></thead>
    <tbody>{asset_rows or '<tr><td colspan="2">No assets</td></tr>'}</tbody>
  </table>

  <div class="footer">
    Generated by HelixAudit v1.7.0 • Authorized testing only • Confidential<br/>
    Coverage matrix shows what was tested. Full VAPT sign-off still requires expert manual review.
  </div>
</body></html>"""
    return HTMLResponse(content=html)


@router.get("/scans/{scan_id}/export")
def export_scan_json(scan_id: int, db: Session = Depends(get_db)):
    """Machine-readable JSON export of scan results."""
    data = _build_report_data(db, scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan, project, findings, assets, counts = (
        data["scan"], data["project"], data["findings"], data["assets"], data["counts"]
    )
    return {
        "scan": {
            "id": scan.id,
            "target": scan.target,
            "status": scan.status,
            "progress": scan.progress,
            "started_at": str(scan.started_at) if scan.started_at else None,
            "completed_at": str(scan.completed_at) if scan.completed_at else None,
        },
        "project": {
            "id": project.id if project else None,
            "name": project.name if project else None,
            "client_name": project.client_name if project else None,
        },
        "summary": counts,
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "location": f.location,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "status": f.status,
            }
            for f in findings
        ],
        "assets": [
            {"id": a.id, "type": a.asset_type, "value": a.value}
            for a in assets
        ],
    }


def _pdf_response(scan_id: int, db: Session):
    from fastapi.responses import Response
    from ..services.pdf_report import build_pdf_report

    data = _build_report_data(db, scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    try:
        pdf_bytes = build_pdf_report(
            data["scan"], data["project"], data["findings"], data["assets"], data["counts"]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)[:300]}")
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=helixaudit-scan-{scan_id}.pdf"},
    )


@router.get("/scans/{scan_id}/report.pdf")
def generate_pdf_report(scan_id: int, db: Session = Depends(get_db)):
    return _pdf_response(scan_id, db)


@router.get("/scans/{scan_id}/report/pdf")
def generate_pdf_report_alt(scan_id: int, db: Session = Depends(get_db)):
    """Alternate path for clients that mishandle .pdf in the URL."""
    return _pdf_response(scan_id, db)




@router.get("/scans/{scan_id}/burp")
def export_burp_package(scan_id: int, db: Session = Depends(get_db)):
    """Export scan as Burp Suite handoff package (scope + URLs + issues)."""
    from ..services.burp_export import build_burp_package
    data = _build_report_data(db, scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    return build_burp_package(data["scan"], data["assets"], data["findings"])


@router.get("/scans/{scan_id}/burp/urls.txt")
def export_burp_urls_txt(scan_id: int, db: Session = Depends(get_db)):
    """Plain URL list for Burp Target / Intruder paste."""
    from fastapi.responses import PlainTextResponse
    from ..services.burp_export import build_burp_package
    data = _build_report_data(db, scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    pkg = build_burp_package(data["scan"], data["assets"], data["findings"])
    return PlainTextResponse(pkg["url_list_text"] or "", media_type="text/plain")


@router.post("/scans/{scan_id}/burp/push")
async def push_to_burp(scan_id: int, db: Session = Depends(get_db)):
    """Optional: push discovered URLs to local/remote Burp REST API."""
    from ..services.burp_export import build_burp_package, push_urls_to_burp_api
    from ..core.config import settings
    if not settings.BURP_API_URL:
        raise HTTPException(
            status_code=400,
            detail="BURP_API_URL not configured. Export /burp package and import into Burp manually.",
        )
    data = _build_report_data(db, scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    pkg = build_burp_package(data["scan"], data["assets"], data["findings"])
    result = await push_urls_to_burp_api(
        settings.BURP_API_URL, pkg["urls"], settings.BURP_API_KEY
    )
    return {"scan_id": scan_id, "burp_api": settings.BURP_API_URL, **result}


@router.get("/pipeline/suites")
def pipeline_suites():
    """List Top Suite profiles for scans."""
    from ..pipeline.suites import list_suites
    return list_suites()


@router.get("/pipeline/tools")
def list_pipeline_tools():
    """List registered pipeline tools in execution order."""
    from ..pipeline.engine import default_tool_chain
    tools = default_tool_chain()
    return [
        {"name": t.name, "description": t.description, "order": t.order}
        for t in sorted(tools, key=lambda x: x.order)
    ]


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: int, db: Session = Depends(get_db)):
    """Mark a stuck/running scan as failed so a new one can be started cleanly."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status in ("completed", "failed", "cancelled"):
        return {"id": scan.id, "status": scan.status, "message": "already finished"}
    scan.status = "failed"
    scan.error_message = "Cancelled or marked failed (was stuck/running too long)"
    scan.progress = 100
    from datetime import datetime
    scan.completed_at = datetime.utcnow()
    db.commit()
    return {"id": scan.id, "status": scan.status, "message": "cancelled"}


@router.get("/scans/compare")
def compare_scans(scan_a: int, scan_b: int, db: Session = Depends(get_db)):
    """Compare two scans: new issues, fixed issues, unchanged."""
    a = db.query(Scan).filter(Scan.id == scan_a).first()
    b = db.query(Scan).filter(Scan.id == scan_b).first()
    if not a or not b:
        raise HTTPException(status_code=404, detail="Scan not found")
    fa = db.query(Finding).filter(Finding.scan_id == scan_a).all()
    fb = db.query(Finding).filter(Finding.scan_id == scan_b).all()

    def key(f):
        return ((f.title or "")[:80].lower(), (f.location or "")[:80].lower())

    map_a = {key(f): f for f in fa if (f.category or "") != "Executive Summary"}
    map_b = {key(f): f for f in fb if (f.category or "") != "Executive Summary"}
    keys_a, keys_b = set(map_a), set(map_b)
    new_in_b = keys_b - keys_a
    gone_in_b = keys_a - keys_b
    same = keys_a & keys_b
    return {
        "scan_a": scan_a,
        "scan_b": scan_b,
        "new_in_b": [{"title": map_b[k].title, "severity": map_b[k].severity, "location": map_b[k].location} for k in list(new_in_b)[:50]],
        "resolved_since_a": [{"title": map_a[k].title, "severity": map_a[k].severity, "location": map_a[k].location} for k in list(gone_in_b)[:50]],
        "unchanged": len(same),
        "counts": {
            "a_total": len(map_a),
            "b_total": len(map_b),
            "new": len(new_in_b),
            "resolved": len(gone_in_b),
        },
    }


@router.post("/findings/{finding_id}/retest")
def retest_finding(finding_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Create a focused follow-up scan on the finding location/target."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    parent = db.query(Scan).filter(Scan.id == finding.scan_id).first()
    if not parent:
        raise HTTPException(status_code=404, detail="Parent scan not found")
    target = finding.location or parent.target
    # Prefer origin if location is a full URL path-only issue
    if target.startswith("/"):
        target = parent.target
    new_scan = Scan(
        project_id=parent.project_id,
        target=target,
        scan_type="retest",
        status=ScanStatus.PENDING.value,
        config={"retest_of_finding": finding_id, "parent_scan": parent.id},
    )
    db.add(new_scan)
    finding.status = "retest"
    db.commit()
    db.refresh(new_scan)
    background_tasks.add_task(run_discovery_scan, new_scan.id)
    return {"scan_id": new_scan.id, "status": "started", "retest_of": finding_id}
