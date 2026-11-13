# HelixAudit Automated VAPT-Assist Pipeline

## Important
This is **VAPT assistance**, not a full legal VAPT sign-off by itself.
Full VAPT needs scope/RoE, manual testing, business logic, and expert validation.

## Sequential chain (URL → report)
1. subfinder / subdomain enum  
2. DNS email security (MX/SPF/DMARC)  
3. ports  
4. httpx live probe  
5. WAF detect  
6. SSL/TLS  
7. HTTPS redirect  
8. tech detect  
9. crawl  
10. sitemap  
11. API discover  
12. robots/security.txt  
13. sensitive paths  
14. secrets  
15. OWASP surface  
16. active checks (CORS/methods/files)  
17. injection detection probes  
18. nuclei templates  
19. VAPT summary  
(+ optional authenticated deep stage if credentials provided)

## Adding more tools
Create `backend/app/pipeline/tools/my_tool.py` with `BaseTool`, register in `default_tool_chain()`.
