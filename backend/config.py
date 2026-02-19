import os
from dotenv import load_dotenv

load_dotenv()


def _get_required_env(name: str) -> str:
	value = os.getenv(name)
	if not value:
		raise ValueError(f"Missing required env var: {name}")
	return value


GOOGLE_CLIENT_ID = _get_required_env("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = _get_required_env("GOOGLE_CLIENT_SECRET")

MICROSOFT_CLIENT_ID = _get_required_env("MICROSOFT_CLIENT_ID")
MICROSOFT_CLIENT_SECRET = _get_required_env("MICROSOFT_CLIENT_SECRET")
MICROSOFT_TENANT_ID = _get_required_env("MICROSOFT_TENANT_ID")

BACKEND_BASE_URL = _get_required_env("BACKEND_BASE_URL")
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "http://localhost:3000")
DATABASE_URL = _get_required_env("DATABASE_URL")
DEFAULT_ORG_NAME = os.getenv("ORG_NAME", "default")

_cors_env = os.getenv("CORS_ORIGINS", FRONTEND_BASE_URL)
CORS_ORIGINS = [origin.strip() for origin in _cors_env.split(",") if origin.strip()]
