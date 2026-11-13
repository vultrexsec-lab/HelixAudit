# Phases A / B / C

## Phase A ✅
- Authenticated deep scan after login
- Public vs Authenticated report sections
- Exposure tags + risk scores in UI

## Phase B ✅
- Email notify on scan complete (SMTP env)
- White-label PDF branding (BRAND_* env + client_name)
- HTML report “Prepared for” client

## Phase C ✅
- baseline_files tool (robots.txt / security.txt)
- install_tools.sh improved (nuclei templates update)
- Pipeline: subfinder → … → baseline → … → nuclei

## Configure email (Render env)
SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM, NOTIFY_EMAIL_TO, SMTP_TLS=true

## Configure brand
BRAND_COMPANY_NAME, BRAND_REPORT_FOOTER

## Render build
pip install -r requirements.txt && bash scripts/install_tools.sh
