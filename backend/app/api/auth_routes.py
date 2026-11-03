from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from typing import Optional, List
from ..core.database import get_db
from ..core.auth import (
    hash_password, verify_password, create_access_token,
    get_current_user, require_user, ACCESS_TOKEN_EXPIRE_MINUTES,
)
from ..models.models import User, Schedule, Project, Scan, ScanStatus
from ..services.scan_service import run_discovery_scan
from fastapi import BackgroundTasks
from datetime import datetime, timedelta as td

router = APIRouter(prefix="/auth", tags=["auth"])
schedule_router = APIRouter(prefix="/schedules", tags=["schedules"])


class RegisterIn(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None


class UserOut(BaseModel):
    id: int
    email: str
    full_name: Optional[str]
    is_admin: bool

    class Config:
        from_attributes = True


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


@router.post("/register", response_model=UserOut)
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    if len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    user = User(
        email=payload.email.lower(),
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        is_admin=db.query(User).count() == 0,  # first user is admin
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form.username.lower()).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User inactive")
    token = create_access_token(
        {"sub": user.email},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return TokenOut(access_token=token, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(require_user)):
    return user


class ScheduleCreate(BaseModel):
    project_id: int
    target: str
    interval_hours: int = 24
    enabled: bool = True


class ScheduleOut(BaseModel):
    id: int
    project_id: int
    target: str
    interval_hours: int
    enabled: bool
    last_run_at: Optional[datetime]
    next_run_at: Optional[datetime]

    class Config:
        from_attributes = True


@schedule_router.post("", response_model=ScheduleOut)
def create_schedule(payload: ScheduleCreate, db: Session = Depends(get_db), user: User = Depends(require_user)):
    project = db.query(Project).filter(Project.id == payload.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    sched = Schedule(
        project_id=payload.project_id,
        target=payload.target,
        interval_hours=max(1, payload.interval_hours),
        enabled=payload.enabled,
        next_run_at=datetime.utcnow() + td(hours=max(1, payload.interval_hours)),
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)
    return sched


@schedule_router.get("", response_model=List[ScheduleOut])
def list_schedules(db: Session = Depends(get_db), user: User = Depends(require_user)):
    return db.query(Schedule).order_by(Schedule.created_at.desc()).all()


@schedule_router.post("/{schedule_id}/run")
async def run_schedule_now(
    schedule_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    sched = db.query(Schedule).filter(Schedule.id == schedule_id).first()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    scan = Scan(
        project_id=sched.project_id,
        target=sched.target,
        scan_type="discovery",
        status=ScanStatus.PENDING.value,
        config=sched.config,
    )
    db.add(scan)
    sched.last_run_at = datetime.utcnow()
    sched.next_run_at = datetime.utcnow() + td(hours=sched.interval_hours or 24)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(run_discovery_scan, db, scan.id)
    return {"scan_id": scan.id, "status": "started"}
