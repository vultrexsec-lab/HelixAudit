"""
HelixAudit - Professional Authorized Penetration Testing Dashboard
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="HelixAudit",
    description="Sequential, professional, authorized vulnerability assessment and penetration testing platform.",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS (will be restricted in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Restrict to frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {
        "name": "HelixAudit",
        "version": "0.1.0",
        "status": "Phase 0 - Foundation",
        "message": "Authorized use only. Always obtain written permission before scanning.",
        "docs": "/docs"
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}
