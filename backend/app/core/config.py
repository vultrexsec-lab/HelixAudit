from pydantic_settings import BaseSettings
from typing import Optional, List


class Settings(BaseSettings):
    PROJECT_NAME: str = "HelixAudit"
    VERSION: str = "0.8.0-phase8"
    API_V1_STR: str = "/api/v1"
    
    # Security
    SECRET_KEY: str = "CHANGE-THIS-IN-PRODUCTION-USE-OPENSSL-RAND-32"
    API_KEY: Optional[str] = None  # Set this in production to protect the API
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7
    
    # Database
    DATABASE_URL: str = "sqlite:///./helixaudit.db"
    
    # CORS - set specific origins in production
    CORS_ORIGINS: str = "*"  # comma-separated or *
    
    # Scanning limits (safety)
    MAX_CONCURRENT_SCANS: int = 2
    DEFAULT_SCAN_TIMEOUT: int = 1800
    MAX_PAGES_CRAWL: int = 25
    MAX_CRAWL_DEPTH: int = 2
    
    class Config:
        env_file = ".env"
        case_sensitive = True

    @property
    def cors_origins_list(self) -> List[str]:
        if self.CORS_ORIGINS.strip() == "*":
            return ["*"]
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


settings = Settings()
