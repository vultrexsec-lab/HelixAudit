import os
import shutil
from pathlib import Path

# backend/app/pipeline -> backend
_BACKEND = Path(__file__).resolve().parents[1]
_BIN = _BACKEND / "bin"


def find_binary(name: str) -> str | None:
    """Find tool binary in backend/bin or system PATH."""
    candidate = _BIN / name
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    # Avoid python httpx shadowing projectdiscovery httpx
    path = shutil.which(name)
    if path and name == "httpx":
        # prefer our bin copy
        if candidate.is_file():
            return str(candidate)
        # skip if it's the python one (heuristic)
        try:
            import subprocess
            r = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=5)
            if "projectdiscovery" in (r.stdout + r.stderr).lower() or "httpx" in (r.stdout + r.stderr).lower():
                if "Usage: httpx [OPTIONS] URL" in (r.stderr or ""):
                    return None
                return path
        except Exception:
            return None
    return path
