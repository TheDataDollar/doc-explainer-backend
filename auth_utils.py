from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
import os

# ✅ Use env if present (Render), fallback for local dev
JWT_SECRET = (os.getenv("JWT_SECRET") or "change_me_super_long").strip()
JWT_ALG = "HS256"
ACCESS_TOKEN_MINUTES = 60 * 24 * 7  # 7 days

# ✅ Use PBKDF2 instead of bcrypt (more stable on Windows)
pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto"
)

def hash_password(password: str) -> str:
    return pwd_context.hash(password.strip())

def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password.strip(), password_hash)

def create_access_token(user_id: int) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    payload = {"sub": str(user_id), "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def decode_access_token(token: str) -> int:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        sub = payload.get("sub")
        if not sub:
            raise ValueError("Missing sub")
        return int(sub)
    except (JWTError, ValueError):
        raise ValueError("Invalid token")
