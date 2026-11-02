"""
HelixAudit - Phase 1
Professional Authorized Penetration Testing Dashboard
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api.routes import router
from .core.config import settings

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Sequential, professional, authorized vulnerability assessment platform. Phase 1: Foundation + Strong Discovery",
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix=settings.API_V1_STR)


@app.get("/")
async def root():
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "phase": "Phase 3 - Deep Analysis + Secrets Detection",
        "message": "Authorized use only. Always obtain written permission before scanning any target.",
        "docs": "/docs",
        "features": [
            "Project Management",
            "Subdomain Enumeration",
            "Port & Service Scanning (Nmap)",
            "Basic Technology Detection",
            "Findings with Evidence"
        ]
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "phase": "3"}
