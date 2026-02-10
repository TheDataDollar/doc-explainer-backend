from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy.exc import OperationalError
import os
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
import requests
import stripe

# ---------------- DATABASE ----------------

from deps import get_db, engine
from db import Base, User, Document, PasswordResetToken

# IMPORTANT: import affiliate model so table is created
from models_affiliate import AffiliateAccount  # noqa: F401
from routers.affiliate_admin import router as affiliate_admin_router
app.include_router(affiliate_admin_router)


# ---------------- AUTH ----------------

from auth_deps import get_current_user
from admin_auth import require_admin
from auth_utils import hash_password, verify_password, create_access_token

# ---------------- APP ----------------

app = FastAPI(title="Document Explainer API")

# ---------------- ROUTERS ----------------

from routers.affiliate_auth import router as affiliate_auth_router
app.include_router(affiliate_auth_router)

# ---------------- STARTUP ----------------

@app.on_event("startup")
def on_startup():
    try:
        Base.metadata.create_all(bind=engine)
        print("✅ Database tables ensured")
    except OperationalError as e:
        print("⚠️ Database not reachable at startup")
        print(e)

# ---------------- CORS ----------------

ENV = os.getenv("ENV", "development").lower()

raw_origins = os.getenv("CORS_ORIGINS", "").strip()
allow_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]
allow_origin_regex = os.getenv("CORS_ORIGIN_REGEX", "").strip() or None

if ENV != "production" and not allow_origins:
    allow_origins = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://document-explainer-blond.vercel.app",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_origin_regex=allow_origin_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- HELPERS ----------------

FRONTEND_URL = os.getenv("FRONTEND_URL", "https://document-explainer-blond.vercel.app")
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
FROM_EMAIL = os.getenv("FROM_EMAIL", "Document Explainer <onboarding@resend.dev>")

def utcnow():
    return datetime.now(timezone.utc)

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def send_reset_email(to_email: str, reset_link: str):
    if not RESEND_API_KEY:
        print("🔑 RESET LINK:", reset_link)
        return

    requests.post(
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "from": FROM_EMAIL,
            "to": [to_email],
            "subject": "Reset your password",
            "html": f"<a href='{reset_link}'>Reset password</a>",
        },
        timeout=10,
    )

# ---------------- STRIPE ----------------

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

# ---------------- HEALTH ----------------

@app.get("/health")
def health():
    return {"ok": True}

# ---------------- AUTH MODELS ----------------

class RegisterBody(BaseModel):
    email: EmailStr
    password: str

class LoginBody(BaseModel):
    email: EmailStr
    password: str

class ForgotPasswordBody(BaseModel):
    email: EmailStr

class ResetPasswordBody(BaseModel):
    token: str
    new_password: str

# ---------------- AUTH ROUTES ----------------

@app.post("/auth/register")
def register(body: RegisterBody, db: Session = Depends(get_db)):
    email = body.email.lower().strip()

    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=email,
        password_hash=hash_password(body.password),
        free_docs_used=0,
        is_paid=False,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return {"user_id": user.id, "token": create_access_token(user.id)}

@app.post("/auth/login")
def login(body: LoginBody, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email.lower()).first()

    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {
        "user_id": user.id,
        "token": create_access_token(user.id),
        "free_docs_used": user.free_docs_used,
        "is_paid": user.is_paid,
    }

# ---------------- USER ----------------

@app.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return {
        "user_id": current_user.id,
        "email": current_user.email,
        "free_docs_used": current_user.free_docs_used,
        "is_paid": current_user.is_paid,
        "plan_tier": current_user.plan_tier,
    }

# ---------------- DOCUMENTS ----------------

@app.post("/documents/upload")
def upload_document(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not current_user.is_paid and current_user.free_docs_used >= 3:
        raise HTTPException(status_code=402, detail="Free limit reached")

    os.makedirs("storage", exist_ok=True)

    stored_filename = f"{uuid.uuid4().hex}{os.path.splitext(file.filename)[1]}"
    stored_path = os.path.join("storage", stored_filename)

    with open(stored_path, "wb") as f:
        f.write(file.file.read())

    doc = Document(
        user_id=current_user.id,
        original_filename=file.filename,
        stored_filename=stored_filename,
        stored_path=stored_path,
    )

    db.add(doc)

    if not current_user.is_paid:
        current_user.free_docs_used += 1

    db.commit()
    db.refresh(doc)

    return {"document_id": doc.id}

# ---------------- ADMIN ----------------

@app.get("/admin/users")
def admin_list_users(
    db: Session = Depends(get_db),
    _admin=Depends(require_admin),
):
    return db.query(User).all()
