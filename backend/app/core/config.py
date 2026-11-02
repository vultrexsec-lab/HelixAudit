from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    PROJECT_NAME: str = "HelixAudit"
    VERSION: str = "0.3.0-phase3"
    API_V1_STR: str = "/api/v1"
    
    # Security
    SECRET_KEY: str = "CHANGE-THIS-IN-PRODUCTION-USE-STRONG-RANDOM-VALUE"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7
    
    # Database
    DATABASE_URL: str = "sqlite:///./helixaudit.db"
    
    # Scanning limits
    MAX_CONCURRENT_SCANS: int = 2
    DEFAULT_SCAN_TIMEOUT: int = 1800  # 30 minutes
    SUBDOMAIN_ENUM_TIMEOUT: int = 300
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
