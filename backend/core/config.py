import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Hybrid EDR Platform - API Gateway"
    API_V1_STR: str = "/api/v1"
    
    # Upload Settings
    MAX_UPLOAD_SIZE: int = int(os.getenv("MAX_UPLOAD_SIZE", 50 * 1024 * 1024)) # 50 MB default
    ALLOWED_EXTENSIONS: set = {".exe", ".elf", ".dll", ".so", ".bin", ".sh", ".py", ".pdf", ".doc", ".docx"}
    
    # Database Config
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql+asyncpg://admin:pass@localhost:5432/edr")
    
    # Redis Config (Session, Cache, Rate Limits)
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    # Message Broker
    RABBITMQ_URL: str = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
    
    # Object Storage
    S3_ENDPOINT: str = os.getenv("S3_ENDPOINT", "http://localhost:9000")
    S3_BUCKET: str = os.getenv("S3_BUCKET", "malware-samples")
    S3_ACCESS_KEY: str = os.getenv("S3_ACCESS_KEY", "minioadmin")
    S3_SECRET_KEY: str = os.getenv("S3_SECRET_KEY", "minioadmin")
    
    # Security Auth Hash (Agent basic auth)
    # Using bcrypt hash for prod-agent-key-change-me: $2b$12$6/7n.P7S39...
    AGENT_API_HASH: str = os.getenv("AGENT_API_HASH", "$2b$12$R.O/7tZ1S0/HHTlY5.8HnuA1L0l7a9V8uLpY0pL9qH1I0vXJ.K36q")

    # Detection thresholds (tunable)
    SUSPICIOUS_THRESHOLD: float = float(os.getenv("SUSPICIOUS_THRESHOLD", "40"))
    MALICIOUS_THRESHOLD: float = float(os.getenv("MALICIOUS_THRESHOLD", "70"))

    # Agent poll tuning
    REPORT_POLL_BASE_DELAY_SEC: int = int(os.getenv("REPORT_POLL_BASE_DELAY_SEC", "2"))
    REPORT_POLL_MAX_DELAY_SEC: int = int(os.getenv("REPORT_POLL_MAX_DELAY_SEC", "12"))
    REPORT_POLL_MAX_ATTEMPTS: int = int(os.getenv("REPORT_POLL_MAX_ATTEMPTS", "8"))

settings = Settings()
