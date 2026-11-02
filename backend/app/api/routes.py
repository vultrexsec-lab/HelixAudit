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
    
    db_scan = Scan(
        project_id=scan.project_id,
        target=scan.target,
        scan_type=scan.scan_type,
        status=ScanStatus.PENDING.value
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


# ---------- Phase 5: Finding Lifecycle + Report ----------

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


@router.get("/scans/{scan_id}/report")
def generate_report(scan_id: int, db: Session = Depends(get_db)):
    """Generate a simple professional HTML report for the scan."""
    from fastapi.responses import HTMLResponse

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    project = db.query(Project).filter(Project.id == scan.project_id).first()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).order_by(Finding.severity).all()
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_sorted = sorted(findings, key=lambda f: severity_order.get(f.severity, 5))

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    rows = ""
    for f in findings_sorted:
        rows += f"""
        <tr>
          <td><span class="sev {f.severity}">{f.severity.upper()}</span></td>
          <td>{f.title or ''}</td>
          <td>{f.category or ''}</td>
          <td>{f.location or ''}</td>
          <td>{f.status or 'new'}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>HelixAudit Report - Scan #{scan.id}</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1e293b; }}
  h1 {{ color: #0f172a; }}
  .meta {{ color: #64748b; margin-bottom: 1.5rem; }}
  .summary {{ display: flex; gap: 1rem; margin: 1.5rem 0; flex-wrap: wrap; }}
  .box {{ background: #f1f5f9; padding: 1rem 1.25rem; border-radius: 8px; min-width: 100px; text-align: center; }}
  .box strong {{ display: block; font-size: 1.5rem; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
  th, td {{ text-align: left; padding: 0.6rem; border-bottom: 1px solid #e2e8f0; font-size: 0.9rem; }}
  th {{ background: #f8fafc; }}
  .sev {{ padding: 0.15rem 0.45rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
  .critical {{ background: #fee2e2; color: #991b1b; }}
  .high {{ background: #ffedd5; color: #9a3412; }}
  .medium {{ background: #fef3c7; color: #92400e; }}
  .low {{ background: #dbeafe; color: #1e40af; }}
  .info {{ background: #f1f5f9; color: #475569; }}
  .footer {{ margin-top: 2rem; font-size: 0.8rem; color: #94a3b8; }}
</style></head>
<body>
  <h1>HelixAudit Security Assessment Report</h1>
  <div class="meta">
    <div><strong>Project:</strong> {project.name if project else 'N/A'}</div>
    <div><strong>Target:</strong> {scan.target}</div>
    <div><strong>Scan ID:</strong> #{scan.id} &nbsp;|&nbsp; <strong>Status:</strong> {scan.status}</div>
    <div><strong>Started:</strong> {scan.started_at} &nbsp;|&nbsp; <strong>Completed:</strong> {scan.completed_at}</div>
  </div>

  <h2>Summary</h2>
  <div class="summary">
    <div class="box"><strong>{counts['critical']}</strong>Critical</div>
    <div class="box"><strong>{counts['high']}</strong>High</div>
    <div class="box"><strong>{counts['medium']}</strong>Medium</div>
    <div class="box"><strong>{counts['low']}</strong>Low</div>
    <div class="box"><strong>{counts['info']}</strong>Info</div>
    <div class="box"><strong>{len(assets)}</strong>Assets</div>
  </div>

  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Title</th><th>Category</th><th>Location</th><th>Status</th></tr></thead>
    <tbody>{rows or '<tr><td colspan="5">No findings</td></tr>'}</tbody>
  </table>

  <div class="footer">
    Generated by HelixAudit • Authorized testing only • This report is confidential.
  </div>
</body></html>"""
    return HTMLResponse(content=html)
