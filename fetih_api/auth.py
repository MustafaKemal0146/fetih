"""API Key doğrulama."""
from __future__ import annotations
import os
import secrets
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer(auto_error=False)


def get_api_key() -> str:
    """.env veya FETIH_API_KEY env'den API key'i oku."""
    # Önce direkt env
    key = os.environ.get("FETIH_API_KEY", "")
    if key:
        return key
    # .env dosyasından
    env_path = os.path.expanduser("~/.fetih/.env")
    try:
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("FETIH_API_KEY="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return ""


def require_auth(credentials: HTTPAuthorizationCredentials | None = Security(security)):
    """API key doğrulaması (opsiyonel)."""
    expected = get_api_key()
    # API key tanımlanmamışsa auth'suz erişime izin ver
    if not expected:
        return True
    if not credentials:
        raise HTTPException(status_code=401, detail="API key required. Use: Authorization: Bearer <key>")
    if not secrets.compare_digest(credentials.credentials, expected):
        raise HTTPException(status_code=403, detail="Invalid API key")
    return True
