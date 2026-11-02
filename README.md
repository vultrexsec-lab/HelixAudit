# HelixAudit

**HelixAudit** is a professional, sequential, authorized penetration testing and vulnerability assessment platform.

> **⚠️ STRICTLY FOR AUTHORIZED USE ONLY**  
> Only scan systems you own or have explicit written permission (Rules of Engagement) to test. Unauthorized testing is illegal.

## Current Status: Phase 1 Complete

**Phase 1 – Foundation + Strong Discovery** includes:

- Project & Scan management
- Subdomain enumeration
- Port & Service scanning (Nmap)
- Basic Technology detection
- Findings storage with evidence
- Clean REST API

### API Documentation
Once running: http://localhost:8000/docs

### Quick Start (Local)

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Main Endpoints

- `POST /api/v1/projects` – Create project
- `GET  /api/v1/projects` – List projects
- `POST /api/v1/scans` – Start a discovery scan
- `GET  /api/v1/scans/{id}` – Scan status
- `GET  /api/v1/scans/{id}/assets` – Discovered assets
- `GET  /api/v1/scans/{id}/findings` – Findings with evidence

## Roadmap

- **Phase 1**: Foundation + Strong Discovery ✅
- **Phase 2**: Deep Crawling & Content Collection
- **Phase 3**: Deep Analysis + Secrets/Password Leak Detection
- **Phase 4**: OWASP Top 10 + Authenticated Scanning
- **Phase 5**: Professional Reporting & Finding Lifecycle
- **Phase 6**: Hardening, Polish & Deployment

## License
Private – All rights reserved.
