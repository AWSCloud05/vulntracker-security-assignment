import os

# Database URL: SQLite for local development; use a managed database in production.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vulntracker.db")

# Required secret: provide a strong value through the environment.
SECRET_KEY = os.getenv("SECRET_KEY", "")
if len(SECRET_KEY) < 32:
    raise RuntimeError("SECRET_KEY must be set and contain at least 32 characters")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Public URL used when generating shared report links.
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")

# Production must use HTTPS.
if os.getenv("APP_ENV", "development").lower() == "production":
    if not PUBLIC_BASE_URL.startswith("https://"):
        raise RuntimeError("PUBLIC_BASE_URL must use HTTPS in production")

NOTIFY_SERVICE_URL = os.getenv(
    "NOTIFY_SERVICE_URL",
    "http://localhost:3001"
)


# Shared key used only for Python-to-Node internal service authentication.
NOTIFY_SERVICE_KEY = os.getenv("NOTIFY_SERVICE_KEY", "")
if len(NOTIFY_SERVICE_KEY) < 32:
    raise RuntimeError("NOTIFY_SERVICE_KEY must contain at least 32 characters")
