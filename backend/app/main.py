"""
HelixAudit - Professional Authorized Security Scanner
Phase 6: Hardened & Production Ready
"""

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from .api.routes import router
from .core.config import settings
from .core.security import verify_api_key

app = FastAPI(
    title=settings.PROJECT_NAME,
    description=(
        "Sequential, professional, authorized vulnerability assessment platform.\n\n"
        "⚠️ AUTHORIZED USE ONLY. Only scan systems you own or have written permission to test."
    ),
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

# All API routes (optional API key protection via dependency where needed)
app.include_router(router, prefix=settings.API_V1_STR)


@app.get("/")
async def root():
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "phase": "Phase 7 - Enhanced UX + Reporting",
        "message": "Authorized use only. Always obtain written permission before scanning.",
        "docs": "/docs",
        "features": [
            "Project & Scan Management",
            "Subdomain Enumeration",
            "Port & Service Scanning",
            "Deep Crawling & Content Discovery",
            "Secrets / Sensitive Data Detection",
            "OWASP Top 10 Oriented Checks",
            "Finding Lifecycle Management",
            "Professional HTML Reports"
        ]
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "phase": "7"
    }


@app.get("/version")
async def version():
    return {"version": settings.VERSION, "name": settings.PROJECT_NAME}
