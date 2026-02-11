# routers/affiliate_auth.py (FULL COPY / REPLACE)

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
import secrets
import time
import os

from jose import jwt
from passlib.context import CryptContext

from deps import get_db
from models_affiliate import AffiliateAccount

router = APIRouter(prefix="/affiliate", tags=["Affiliate"])

# ✅ Use PBKDF2 (stable on Windows)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

JWT_SECRET = os.getenv("AFFILIATE_JWT_SECRET") or os.getenv("JWT_SECRET") or "change_me_super_long"
JWT_ALG = "HS256"
TOKEN_DAYS = 7


def hash_password(p: str) -> str:
    return pwd_context.hash(p.strip())


def verify_password(p: str, hashed: str) -> bool:
    return pwd_context.verify(p.strip(), hashed)


def generate_ref_code() -> str:
    return secrets.token_hex(4).upper()


def create_affiliate_token(affiliate_id: int) -> str:
    now = int(time.time())
    payload = {
        "sub": f"affiliate:{affiliate_id}",
        "role": "affiliate",
        "iat": now,
        "exp": now + 60 * 60 * 24 * TOKEN_DAYS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


class AffiliateRegisterIn(BaseModel):
    email: EmailStr
    password: str
    display_name: str | None = None


class AffiliateLoginIn(BaseModel):
    email: EmailStr
    password: str


@router.post("/auth/register")
def register(payload: AffiliateRegisterIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()

    existing = db.query(AffiliateAccount).filter(AffiliateAccount.email == email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    ref_code = generate_ref_code()
    while db.query(AffiliateAccount).filter(AffiliateAccount.ref_code == ref_code).first():
        ref_code = generate_ref_code()

    acc = AffiliateAccount(
        email=email,
        password_hash=hash_password(payload.password),
        display_name=payload.display_name,
        status="pending",
        ref_code=ref_code,
        commission_rate=0.30,
    )
    db.add(acc)
    db.commit()
    db.refresh(acc)

    return {"ok": True, "status": acc.status, "message": "Application received. Pending approval."}


@router.post("/auth/login")
def login(payload: AffiliateLoginIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()

    acc = db.query(AffiliateAccount).filter(AffiliateAccount.email == email).first()
    if not acc or not verify_password(payload.password, acc.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if (acc.status or "").lower() != "approved":
        raise HTTPException(status_code=403, detail="Not approved yet")

    token = create_affiliate_token(acc.id)
    return {"access_token": token, "token_type": "bearer"}


def get_current_affiliate_from_token(token: str, db: Session) -> AffiliateAccount:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])

        if payload.get("role") != "affiliate":
            raise Exception("bad role")

        sub = payload.get("sub", "")
        if not isinstance(sub, str) or not sub.startswith("affiliate:"):
            raise Exception("bad sub")

        affiliate_id = int(sub.split(":", 1)[1])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    acc = db.query(AffiliateAccount).filter(AffiliateAccount.id == affiliate_id).first()
    if not acc:
        raise HTTPException(status_code=401, detail="Invalid token")

    return acc


@router.get("/me")
def me(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = authorization.split(" ", 1)[1].strip()
    acc = get_current_affiliate_from_token(token, db)

    return {
        "id": acc.id,
        "email": acc.email,
        "display_name": acc.display_name,
        "status": acc.status,
        "ref_code": acc.ref_code,
        "commission_rate": acc.commission_rate,
        "clicks": 0,
        "signups": 0,
        "paid_conversions": 0,
    }
