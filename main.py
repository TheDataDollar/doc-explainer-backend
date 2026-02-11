# main.py (FULL COPY / REPLACE)

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy.exc import OperationalError
import os
import uuid
import hashlib
from datetime import datetime, timezone
import requests
import stripe

# ✅ AI services
from services.pdf_text import extract_text_from_pdf_path
from services.ai_analyzer import analyze_document_text

# ---------------- DATABASE ----------------
from deps import get_db, engine
from db import Base, User, Document, PasswordResetToken

# IMPORTANT: import affiliate models so tables are created
from models_affiliate import AffiliateAccount  # noqa: F401
from models_affiliate_tracking import (  # noqa: F401
    AffiliateClick,
    AffiliateReferral,
    AffiliateCommissionLedger,
)

# ---------------- AUTH ----------------
from auth_deps import get_current_user
from admin_auth import require_admin
from auth_utils import hash_password, verify_password, create_access_token

# ---------------- APP ----------------
app = FastAPI(title="Document Explainer API")

# ---------------- ROUTERS ----------------
from routers.affiliate_auth import router as affiliate_auth_router
from routers.affiliate_admin import router as affiliate_admin_router

app.include_router(affiliate_auth_router)
app.include_router(affiliate_admin_router)

# (Optional) If you created routers/ai_test.py from earlier step, include it safely:
try:
    from routers.ai_test import router as ai_test_router
    app.include_router(ai_test_router)
except Exception:
    # If file doesn't exist yet, don't crash deploy
    pass

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

    try:
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
    except Exception as e:
        print("⚠️ Resend failed:", str(e))
        print("🔑 RESET LINK:", reset_link)

# ---------------- STRIPE ----------------
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "").strip()
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()

PRO_MONTHLY_PRICE_ID = os.getenv("PRO_MONTHLY_PRICE_ID", "").strip()
PRO_YEARLY_PRICE_ID = os.getenv("PRO_YEARLY_PRICE_ID", "").strip()
BUSINESS_MONTHLY_PRICE_ID = os.getenv("BUSINESS_MONTHLY_PRICE_ID", "").strip()
BUSINESS_YEARLY_PRICE_ID = os.getenv("BUSINESS_YEARLY_PRICE_ID", "").strip()

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

# ---------------- HEALTH ----------------
@app.get("/health")
def health():
    return {"ok": True}

# Quick AI smoke test (works with your existing analyzer)
@app.get("/ai/test")
def ai_test():
    try:
        out = analyze_document_text(
            "This is a test lease. Rent is $1,500 due on the 1st. Late fee is $75 after 5 days."
        )
        # if analyzer returns huge output, keep response small
        preview = out[:800] if isinstance(out, str) else str(out)[:800]
        return {"ok": True, "sample": preview}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ---------------- AUTH MODELS ----------------
class RegisterBody(BaseModel):
    email: EmailStr
    password: str
    # ✅ Affiliate attribution (optional)
    affiliate_ref_code: str | None = None

class LoginBody(BaseModel):
    email: EmailStr
    password: str

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
        plan_tier="free",
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    # ✅ Attach referral if affiliate_ref_code exists
    ref_code = (body.affiliate_ref_code or "").strip().upper()
    if ref_code:
        aff = (
            db.query(AffiliateAccount)
            .filter(AffiliateAccount.ref_code == ref_code)
            .filter(AffiliateAccount.status == "approved")
            .first()
        )
        if aff:
            existing = (
                db.query(AffiliateReferral)
                .filter(AffiliateReferral.referred_user_id == user.id)
                .first()
            )
            if not existing:
                db.add(AffiliateReferral(affiliate_id=aff.id, referred_user_id=user.id))
                db.commit()

    return {"user_id": user.id, "token": create_access_token(user.id)}

@app.post("/auth/login")
def login(body: LoginBody, db: Session = Depends(get_db)):
    email = body.email.lower().strip()
    user = db.query(User).filter(User.email == email).first()

    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {
        "user_id": user.id,
        "token": create_access_token(user.id),
        "free_docs_used": user.free_docs_used,
        "is_paid": user.is_paid,
        "plan_tier": user.plan_tier,
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

# ---------------- BILLING (MINIMUM TO FIX 404s) ----------------
@app.get("/billing/prices")
def billing_prices():
    return {
        "ok": True,
        "prices": {
            "pro": {"monthly": PRO_MONTHLY_PRICE_ID, "yearly": PRO_YEARLY_PRICE_ID},
            "business": {"monthly": BUSINESS_MONTHLY_PRICE_ID, "yearly": BUSINESS_YEARLY_PRICE_ID},
        },
    }

@app.post("/billing/portal")
def billing_portal():
    raise HTTPException(status_code=501, detail="Billing portal not wired in this build yet")

@app.post("/billing/webhook")
async def billing_webhook(_: Request):
    raise HTTPException(status_code=501, detail="Webhook not wired in this build yet")

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

    ext = os.path.splitext(file.filename or "")[1]
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

    # ✅ AI ANALYSIS (best effort) — NEVER breaks upload
    try:
        # Extract text
        text = ""
        if (ext or "").lower() == ".pdf":
            text = extract_text_from_pdf_path(stored_path)

        # Analyze
        ai_output = analyze_document_text(text)

        # Store
        doc.review_notes = ai_output if isinstance(ai_output, str) else str(ai_output)
        doc.status = "completed"
        db.commit()
        db.refresh(doc)

    except Exception as e:
        # keep doc uploaded; show placeholder until you retry later
        doc.status = "uploaded"
        db.commit()
        print("AI analysis failed:", str(e))

    return {"document_id": doc.id, "status": doc.status}

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
