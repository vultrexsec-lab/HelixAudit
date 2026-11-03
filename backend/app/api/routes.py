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
    background_tasks.add_task(run_discovery_scan, db, db_scan.id)
    
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
    """Professional HTML report (print / Save as PDF from browser)."""
    from fastapi.responses import HTMLResponse

    data = _build_report_data(db, scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan, project, findings, assets, counts = (
        data["scan"], data["project"], data["findings"], data["assets"], data["counts"]
    )

    rows = ""
    for f in findings:
        evidence = (f.evidence or "")[:300].replace("<", "&lt;").replace(">", "&gt;")
        remediation = (f.remediation or "")[:250].replace("<", "&lt;").replace(">", "&gt;")
        rows += f"""
        <tr>
          <td><span class="sev {f.severity}">{(f.severity or '').upper()}</span></td>
          <td>
            <strong>{(f.title or '').replace('<','&lt;')}</strong><br/>
            <small>{(f.location or '')}</small>
            {f'<div class="ev">{evidence}</div>' if evidence else ''}
            {f'<div class="rem"><b>Remediation:</b> {remediation}</div>' if remediation else ''}
          </td>
          <td>{(f.category or '')}</td>
          <td>{(f.status or 'new')}</td>
        </tr>"""

    asset_rows = "".join(
        f"<tr><td>{a.asset_type}</td><td>{(a.value or '')[:120]}</td></tr>"
        for a in assets[:100]
    )

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>HelixAudit Report - Scan #{scan.id}</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; margin: 2rem; color: #0f172a; }}
  h1 {{ margin-bottom: 0.25rem; }}
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
  .ev, .rem {{ color: #64748b; font-size: 0.8rem; margin-top: 0.25rem; }}
  .footer {{ margin-top: 2rem; font-size: 0.8rem; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 1rem; }}
  .actions {{ margin: 1rem 0; }}
  .actions button {{ margin-right: 0.5rem; padding: 0.45rem 0.9rem; border-radius: 6px; border: 1px solid #cbd5e1; background: #fff; cursor: pointer; }}
  @media print {{ .actions {{ display: none; }} body {{ margin: 0.5rem; }} }}
</style></head>
<body>
  <h1>HelixAudit Security Assessment Report</h1>
  <div class="meta">
    <div><strong>Project:</strong> {project.name if project else 'N/A'} {f'({project.client_name})' if project and project.client_name else ''}</div>
    <div><strong>Target:</strong> {scan.target}</div>
    <div><strong>Scan ID:</strong> #{scan.id} &nbsp;|&nbsp; <strong>Status:</strong> {scan.status}</div>
    <div><strong>Window:</strong> {scan.started_at} → {scan.completed_at}</div>
  </div>

  <div class="actions">
    <button onclick="window.print()">Print / Save as PDF</button>
  </div>

  <h2>Executive Summary</h2>
  <div class="summary">
    <div class="box"><strong>{counts['critical']}</strong>Critical</div>
    <div class="box"><strong>{counts['high']}</strong>High</div>
    <div class="box"><strong>{counts['medium']}</strong>Medium</div>
    <div class="box"><strong>{counts['low']}</strong>Low</div>
    <div class="box"><strong>{counts['info']}</strong>Info</div>
    <div class="box"><strong>{len(assets)}</strong>Assets</div>
    <div class="box"><strong>{len(findings)}</strong>Findings</div>
  </div>

  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Title / Evidence / Remediation</th><th>Category</th><th>Status</th></tr></thead>
    <tbody>{rows or '<tr><td colspan="4">No findings</td></tr>'}</tbody>
  </table>

  <h2>Discovered Assets (sample)</h2>
  <table>
    <thead><tr><th>Type</th><th>Value</th></tr></thead>
    <tbody>{asset_rows or '<tr><td colspan="2">No assets</td></tr>'}</tbody>
  </table>

  <div class="footer">
    Generated by HelixAudit v0.8 • Authorized testing only • Confidential<br/>
    This automated report supports professional assessment and does not replace expert manual testing.
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
