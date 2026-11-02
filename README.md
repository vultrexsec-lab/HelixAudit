# HelixAudit

**Professional Authorized Security Assessment Platform**

HelixAudit helps security professionals perform structured, sequential reconnaissance and surface analysis on targets they are authorized to test.

> ⚠️ **AUTHORIZED USE ONLY**  
> Only scan systems you own or have explicit written permission (Rules of Engagement) to test. Unauthorized scanning is illegal.

## Current Version: 0.8.0 (Phase 8)

### Features

- Project & Engagement management
- Subdomain enumeration
- Port & Service scanning (Nmap + TCP fallback)
- Deep crawling & content discovery
- Secrets / API key / password pattern detection (with evidence)
- OWASP Top 10 (2025) oriented surface checks
- Finding lifecycle (new → confirmed → false_positive → fixed → retest)
- Professional HTML report generation
- Clean REST API + simple web UI

### Quick Start (Local)

```bash
cd backend
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

- API Docs: http://localhost:8000/docs
- Health: http://localhost:8000/health

### Frontend

Simple UI is in `/frontend`. Point `API_BASE` inside `index.html` to your backend URL, then host on Vercel or any static host.

### Important API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/projects` | Create project |
| POST | `/api/v1/scans` | Start scan |
| GET | `/api/v1/scans/{id}` | Scan status |
| GET | `/api/v1/scans/{id}/findings` | List findings |
| GET | `/api/v1/scans/{id}/assets` | List assets |
| PATCH | `/api/v1/findings/{id}` | Update finding status |
| GET | `/api/v1/scans/{id}/report` | HTML report (Print/PDF)
| GET | `/api/v1/scans/{id}/export` | JSON export |

### Production Notes

- Set `SECRET_KEY` and optionally `API_KEY` in environment
- Restrict `CORS_ORIGINS` to your frontend domain
- Use PostgreSQL for multi-instance deployments
- Always keep scope & written authorization

### Disclaimer

HelixAudit is a security assessment aid. It does not replace manual expert testing. Users are solely responsible for obtaining proper authorization and complying with all applicable laws.

## License
Private – All rights reserved.
