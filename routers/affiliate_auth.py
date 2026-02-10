# routers/affiliate_auth.py

import os
import secrets
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from jose import jwt, JWTError

from deps import get_db
from db import Base  # ✅ Base comes from db
from models_affiliate import AffiliateAccount
from auth_utils import hash_password, verify_password

router = APIRouter(prefix="/affiliate/auth", tags=["Affiliate Auth"])


# ---------------- JWT HELPERS ----------------

JWT_SECRET = (os.getenv("JWT_SECRET") or "change_me_super_long").strip()
JWT_ALG = "HS256"


def create_affiliate_token(affiliate_id: int) -> str:
    payload = {
        "sub": f"affiliate:{affiliate_id}",
        "iat": int(time.time()),
        "exp": int(time.time()) + 60 * 60 * 24 * 7,  # 7 days
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def decode_affiliate_token(token: str) -> int:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        sub = payload.get("sub", "")
        if not sub.startswith("affiliate:"):
            raise JWTError()
        return int(sub.split(":", 1)[1])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ---------------- SCHEMAS ----------------

class AffiliateRegisterIn(BaseModel):
    email: EmailStr
    password: str
    display_name: Optional[str] = None


class AffiliateLoginIn(BaseModel):
    email: EmailStr
    password: str


# ---------------- ROUTES ----------------

@router.post("/register")
def register_affiliate(payload: AffiliateRegisterIn, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()

    if db.query(AffiliateAccount).filter(AffiliateAccount.email == email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    ref_code = secrets.token_hex(4).upper()

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

    return {
        "ok": True,
        "status": acc.status,
        "message": "Affiliate application submitted",
    }


@router.post("/login")
def login_affiliate(payload: AffiliateLoginIn, db: Session = Depends(get_db)):
    acc = (
        db.query(AffiliateAccount)
        .filter(AffiliateAccount.email == payload.email.lower().strip())
        .first()
    )

    if not acc or not verify_password(payload.password, acc.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if acc.status != "approved":
        raise HTTPException(status_code=403, detail="Affiliate not approved")

    token = create_affiliate_token(acc.id)
    return {"access_token": token, "token_type": "bearer"}


@router.get("/me")
def affiliate_me(
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = authorization.split(" ", 1)[1]
    affiliate_id = decode_affiliate_token(token)

    acc = db.query(AffiliateAccount).filter(AffiliateAccount.id == affiliate_id).first()
    if not acc:
        raise HTTPException(status_code=401, detail="Invalid token")

    return {
        "id": acc.id,
        "email": acc.email,
        "display_name": acc.display_name,
        "status": acc.status,
        "ref_code": acc.ref_code,
        "commission_rate": acc.commission_rate,
    }
