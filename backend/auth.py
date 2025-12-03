from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import jwt  # PyJWT
import os
import bcrypt

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.getenv("FASTAPI_SECRET", "change-me-please")
ALGORITHM = "HS256"
DEFAULT_TOKEN_EXPIRE = timedelta(hours=24)


def hash_password(password: str) -> str:
    """Return a bcrypt hash for the provided plain password.
    Attempts passlib first; falls back to direct bcrypt if passlib backend fails.
    """
    try:
        return pwd_context.hash(password)
    except Exception:
        pw = password.encode("utf-8")
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(pw, salt).decode("utf-8")


def verify_password(password: str, hash: str) -> bool:
    """Verify a plain password against its stored hash with passlib or direct bcrypt fallback."""
    try:
        return pwd_context.verify(password, hash)
    except Exception:
        try:
            return bcrypt.checkpw(password.encode("utf-8"), hash.encode("utf-8"))
        except Exception:
            return False


def create_jwt_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT with optional custom expiry (default 24h)."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or DEFAULT_TOKEN_EXPIRE)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_jwt(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT returning its payload."""
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

# Backward compatibility aliases for existing code references
get_password_hash = hash_password
create_access_token = create_jwt_token
decode_access_token = decode_jwt
