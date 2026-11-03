# HelixAudit Tool Pipeline

## Chain order
1. **subfinder** (binary) — passive subdomains  
2. **subdomain_enum** — built-in brute/resolve  
3. **port_scan** — nmap/TCP  
4. **httpx_probe** (binary) — live host probe  
5. **tech_detect** — fingerprint  
6. **crawler** — pages + paths  
7. **secrets_scan** — secret patterns  
8. **owasp_surface** — headers/misconfig  
9. **active_checks** — CORS/methods/files  
10. **injection_detect** — SQLi/XSS probes  
11. **nuclei** (binary) — template vulns  

Each tool gets full context from previous steps.

## Install binaries (server)
```bash
cd backend && bash scripts/install_tools.sh
```

Render build example:
```
pip install -r requirements.txt && bash scripts/install_tools.sh
```

Binaries are not committed (large); installed at deploy time into `backend/bin/`.
