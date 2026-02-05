from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext

# For MVP only. Later move these to .env
JWT_SECRET = "change_me_super_long"
JWT_ALG = "HS256"
ACCESS_TOKEN_MINUTES = 60 * 24 * 7  # 7 days

# ✅ Use PBKDF2 instead of bcrypt (more stable on Windows)
pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto"
)

def hash_password(password: str) -> str:
    # simple safety: strip accidental spaces
    return pwd_context.hash(password.strip())

def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password.strip(), password_hash)

def create_access_token(user_id: int) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    payload = {"sub": str(user_id), "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
