"""
HelixAudit - Authorized Security Assessment Platform
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api.routes import router
from .api.auth_routes import router as auth_router, schedule_router
from .core.config import settings
from .core.database import Base, engine, SessionLocal
from .models import models  # noqa: F401 — register models
from datetime import datetime, timedelta
import asyncio

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Authorized vulnerability assessment platform. Use only with written permission.",
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(schedule_router, prefix=settings.API_V1_STR)
app.include_router(router, prefix=settings.API_V1_STR)


@app.get("/")
async def root():
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "message": "Authorized use only.",
        "docs": "/docs",
        "features": [
            "Multi-user auth (register/login JWT)",
            "Discovery + crawling + secrets",
            "OWASP surface + active checks",
            "SQLi/XSS detection probes",
            "Authenticated scanning",
            "Scheduled scans",
            "HTML + PDF + JSON reports",
            "Finding lifecycle",
        ],
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "version": settings.VERSION}


# ---- Simple in-process scheduler for due schedules ----
_scheduler_started = False


async def _process_due_schedules():
    from .models.models import Schedule, Scan, ScanStatus
    from .services.scan_service import run_discovery_scan

    db = SessionLocal()
    try:
        now = datetime.utcnow()
        due = (
            db.query(Schedule)
            .filter(Schedule.enabled == True, Schedule.next_run_at != None, Schedule.next_run_at <= now)
            .all()
        )
        for sched in due:
            scan = Scan(
                project_id=sched.project_id,
                target=sched.target,
                scan_type="discovery",
                status=ScanStatus.PENDING.value,
                config=sched.config,
            )
            db.add(scan)
            sched.last_run_at = now
            sched.next_run_at = now + timedelta(hours=sched.interval_hours or 24)
            db.commit()
            db.refresh(scan)
            # run in background asyncio task
            asyncio.create_task(run_discovery_scan(SessionLocal(), scan.id))
    except Exception as e:
        print("Scheduler tick error:", e)
    finally:
        db.close()


@app.on_event("startup")
async def startup_event():
    global _scheduler_started
    if _scheduler_started:
        return
    _scheduler_started = True

    async def loop():
        while True:
            await _process_due_schedules()
            await asyncio.sleep(60)  # check every minute

    asyncio.create_task(loop())
