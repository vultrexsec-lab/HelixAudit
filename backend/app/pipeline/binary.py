import os
import shutil
import subprocess
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[1]
_BIN = _BACKEND / "bin"


def find_binary(name: str) -> str | None:
    """Find tool binary in backend/bin or system PATH. Avoid Python httpx CLI."""
    candidate = _BIN / name
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)

    path = shutil.which(name)
    if not path:
        return None

    if name == "httpx":
        try:
            r = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=5)
            out = (r.stdout or "") + (r.stderr or "")
            # Python httpx CLI
            if "Usage: httpx [OPTIONS] URL" in out or "httpx[cli]" in out:
                return None
            if "projectdiscovery" in out.lower() or "Current Version" in out or "v1." in out:
                return path
            # unknown — do not use (risk of wrong binary)
            return None
        except Exception:
            return None

    return path
