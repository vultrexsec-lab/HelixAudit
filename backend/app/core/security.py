"""
Basic security helpers for HelixAudit
"""

import secrets
import hashlib
from fastapi import Header, HTTPException, status
from typing import Optional
from .config import settings


def generate_api_key() -> str:
    return secrets.token_urlsafe(32)


def simple_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


async def verify_api_key(x_api_key: Optional[str] = Header(None)):
    """
    Optional API key protection.
    If HELIX_API_KEY is set in environment, all requests must provide it.
    If not set, API stays open (development mode).
    """
    expected = getattr(settings, "API_KEY", None) or None
    if not expected:
        return True  # open mode

    if not x_api_key or x_api_key != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key. Provide X-API-Key header."
        )
    return True
