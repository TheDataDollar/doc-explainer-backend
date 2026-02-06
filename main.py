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

from deps import get_db, engine
from models import Base, User, Document, PasswordResetToken
from auth_deps import get_current_user
from admin_auth import require_admin
from auth_utils import hash_password, verify_password, create_access_token

app = FastAPI(title="Document Explainer API")

# ---------------- STARTUP ----------------

@app.on_event("startup")
def on_startup():
    try:
        Base.metadata.create_all(bind=engine)
        print("✅ DB tables ensured")
    except OperationalError as e:
        print("⚠️ DB not reachable on startup (local dev). App will still run.")
        print(e)

# ---------------- CORS (LOCKED DOWN) ----------------

ENV = os.getenv("ENV", "development").lower()

raw_origins = os.getenv("CORS_ORIGINS", "").strip()
allow_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]
allow_origin_regex = os.getenv("CORS_ORIGIN_REGEX", "").strip() or None

if ENV == "production":
    if not allow_origins and not allow_origin_regex:
        raise RuntimeError("CORS not configured for production.")
else:
    if not allow_origins:
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
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Accept",
        "Origin",
        "X-Requested-With",
    ],
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
    # If Resend isn't configured, fall back to logs (dev-friendly)
    if not RESEND_API_KEY:
        print("🔑 PASSWORD RESET LINK:", reset_link)
        return

    subject = "Reset your Document Explainer password"
    html = f"""
    <div style="font-family: Arial, sans-serif; line-height: 1.5;">
      <h2 style="margin: 0 0 12px;">Reset your password</h2>
      <p>You requested a password reset. Click the button below:</p>
      <p style="margin: 18px 0;">
        <a href="{reset_link}" style="background:#059669;color:#fff;padding:10px 16px;border-radius:10px;text-decoration:none;display:inline-block;">
          Reset password
        </a>
      </p>
      <p style="color:#6b7280;font-size:12px;">
        If you didn’t request this, you can ignore this email.
      </p>
      <p style="color:#6b7280;font-size:12px;">
        Or copy/paste this link:<br/>
        <span>{reset_link}</span>
      </p>
    </div>
    """

    try:
        r = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "from": FROM_EMAIL,
                "to": [to_email],
                "subject": subject,
                "html": html,
            },
            timeout=10,
        )
        if r.status_code >= 300:
            print("⚠️ Resend email failed:", r.status_code, r.text)
            print("🔑 PASSWORD RESET LINK:", reset_link)
    except Exception as e:
        print("⚠️ Resend request error:", str(e))
        print("🔑 PASSWORD RESET LINK:", reset_link)

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

# ---------------- AUTH ----------------

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

    token = create_access_token(user.id)
    return {"user_id": user.id, "token": token}

@app.post("/auth/login")
def login(body: LoginBody, db: Session = Depends(get_db)):
    email = body.email.lower().strip()
    user = db.query(User).filter(User.email == email).first()

    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(user.id)
    return {
        "user_id": user.id,
        "token": token,
        "free_docs_used": user.free_docs_used,
        "is_paid": user.is_paid,
    }

# ---------------- FORGOT / RESET PASSWORD ----------------

@app.post("/auth/forgot-password")
def forgot_password(
    body: ForgotPasswordBody,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    email = body.email.lower().strip()
    user = db.query(User).filter(User.email == email).first()

    # Always return ok to prevent email enumeration
    if not user:
        return {"ok": True}

    raw_token = secrets.token_urlsafe(32)
    token_hash_value = hash_token(raw_token)

    reset = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash_value,
        expires_at=utcnow() + timedelta(minutes=30),
    )

    db.add(reset)
    db.commit()

    reset_link = f"{FRONTEND_URL}/reset-password?token={raw_token}"
    background_tasks.add_task(send_reset_email, user.email, reset_link)

    return {"ok": True}

@app.post("/auth/reset-password")
def reset_password(body: ResetPasswordBody, db: Session = Depends(get_db)):
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password too short")

    token_hash_value = hash_token(body.token)

    reset = (
        db.query(PasswordResetToken)
        .filter(PasswordResetToken.token_hash == token_hash_value)
        .first()
    )

    if not reset or reset.used_at or reset.expires_at < utcnow():
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user = db.query(User).filter(User.id == reset.user_id).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid token")

    user.password_hash = hash_password(body.new_password)
    reset.used_at = utcnow()

    db.commit()
    return {"ok": True}

# ---------------- USER ----------------

@app.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return {
        "user_id": current_user.id,
        "email": current_user.email,
        "free_docs_used": current_user.free_docs_used,
        "is_paid": current_user.is_paid,
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

    ext = os.path.splitext(file.filename)[1] if file.filename else ""
    stored_filename = f"{uuid.uuid4().hex}{ext}"
    stored_path = os.path.join("storage", stored_filename)

    with open(stored_path, "wb") as f:
        f.write(file.file.read())

    doc = Document(
        user_id=current_user.id,
        original_filename=file.filename or "unknown",
        stored_filename=stored_filename,
        stored_path=stored_path,
        status="uploaded",
    )

    db.add(doc)

    if not current_user.is_paid:
        current_user.free_docs_used += 1

    db.commit()
    db.refresh(doc)

    return {"document_id": doc.id}

@app.get("/documents")
def list_documents(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    docs = (
        db.query(Document)
        .filter(Document.user_id == current_user.id)
        .order_by(Document.id.desc())
        .all()
    )

    return [
        {
            "document_id": d.id,
            "original_filename": d.original_filename,
            "stored_filename": d.stored_filename,
            "created_at": d.created_at,
            "status": d.status,
        }
        for d in docs
    ]

@app.get("/documents/{document_id}")
def get_document(
    document_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    doc = (
        db.query(Document)
        .filter(Document.id == document_id, Document.user_id == current_user.id)
        .first()
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    return {
        "document_id": doc.id,
        "original_filename": doc.original_filename,
        "stored_filename": doc.stored_filename,
        "stored_path": doc.stored_path,
        "created_at": doc.created_at,
        "status": doc.status,
        "review_notes": doc.review_notes,
    }

@app.get("/documents/{document_id}/review")
def get_document_review(
    document_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    doc = (
        db.query(Document)
        .filter(Document.id == document_id, Document.user_id == current_user.id)
        .first()
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    return {
        "document_id": doc.id,
        "status": doc.status,
        "review_notes": doc.review_notes,
        "created_at": doc.created_at,
    }

# ---------------- ADMIN ----------------

@app.get("/admin/users")
def admin_list_users(
    db: Session = Depends(get_db),
    _admin=Depends(require_admin),
):
    return db.query(User).all()
