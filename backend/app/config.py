import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

class Settings(BaseSettings):
    APP_NAME: str = "MailForensics"
    APP_VERSION: str = "1.0.0"
    TAGLINE: str = "Analyze. Investigate. Explain."
    
    # Security & Auth
    SECRET_KEY: str = "mailforensics-defensive-secret-key-change-in-production-32bytes-minimum!"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480 # 8 hours
    
    # Database
    DATABASE_URL: str = "sqlite:///./mailforensics.db"
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20
    DATABASE_POOL_PRE_PING: bool = True
    DATABASE_POOL_RECYCLE: int = 1800
    
    # Asynchronous Queue & Workers
    PROCESSING_MODE: str = "local" # "local" (sync/in-process) or "celery" (distributed task queue)
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = ""
    CELERY_RESULT_BACKEND: str = ""
    
    # Storage Paths
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    STORAGE_DIR: str = os.path.join(BASE_DIR, "storage")
    UPLOAD_DIR: str = os.path.join(STORAGE_DIR, "uploads")
    QUARANTINE_DIR: str = os.path.join(STORAGE_DIR, "quarantine")
    REPORTS_DIR: str = os.path.join(STORAGE_DIR, "reports")
    ATTACHMENTS_DIR: str = os.path.join(STORAGE_DIR, "attachments")
    
    # Safety Limits
    MAX_UPLOAD_SIZE_BYTES: int = 25 * 1024 * 1024  # 25 MB
    MAX_ARCHIVE_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB
    MAX_EXTRACTED_SIZE_BYTES: int = 100 * 1024 * 1024  # 100 MB
    MAX_NESTING_DEPTH: int = 3
    MAX_FILE_COUNT: int = 50
    PARSER_TIMEOUT_SECONDS: int = 15
    
    # Threat Intelligence Keys (Optional - never hardcode defaults with active keys)
    VIRUSTOTAL_API_KEY: str = ""
    ALIENVAULT_OTX_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    
    # Network Security Controls
    ENABLE_LIVE_DNS_LOOKUPS: bool = False # Defensive default: off unless explicitly enabled
    
    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"]
    
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()

# Ensure storage directories exist safely
for path in [settings.STORAGE_DIR, settings.UPLOAD_DIR, settings.QUARANTINE_DIR, settings.REPORTS_DIR, settings.ATTACHMENTS_DIR]:
    os.makedirs(path, exist_ok=True)
