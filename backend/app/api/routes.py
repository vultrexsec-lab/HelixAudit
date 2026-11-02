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
