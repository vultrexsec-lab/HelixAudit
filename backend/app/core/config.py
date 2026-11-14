from pydantic_settings import BaseSettings
from typing import Optional, List


class Settings(BaseSettings):
    PROJECT_NAME: str = "HelixAudit"
    VERSION: str = "1.8.0"
    API_V1_STR: str = "/api/v1"

    SECRET_KEY: str = "CHANGE-THIS-IN-PRODUCTION-USE-OPENSSL-RAND-32"
    API_KEY: Optional[str] = None
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7

    DATABASE_URL: str = "sqlite:///./helixaudit.db"
    CORS_ORIGINS: str = "*"

    MAX_CONCURRENT_SCANS: int = 2
    DEFAULT_SCAN_TIMEOUT: int = 1800
    MAX_PAGES_CRAWL: int = 25
    MAX_CRAWL_DEPTH: int = 2

    # White-label / branding (Phase B)
    BRAND_COMPANY_NAME: str = "HelixAudit"
    BRAND_REPORT_FOOTER: str = "Confidential — Authorized security assessment only"
    BRAND_LOGO_TEXT: str = "HelixAudit"

    # Email notify (Phase B) — also read directly in notify.py via env
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM: Optional[str] = None
    SMTP_TLS: bool = True
    NOTIFY_EMAIL_TO: Optional[str] = None

    class Config:
        env_file = ".env"
        case_sensitive = True

    @property
    def cors_origins_list(self) -> List[str]:
        if self.CORS_ORIGINS.strip() == "*":
            return ["*"]
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


settings = Settings()
