from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy.exc import OperationalError
from sqlalchemy import text
import os
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
import requests

import stripe

from deps import get_db, engine
from models import Base, User, Document, PasswordResetToken
from auth_deps import get_current_user
from admin_auth import require_admin
from auth_utils import hash_password, verify_password, create_access_token

app = FastAPI(title="Document Explainer API")

# ---------------- STARTUP ----------------

def _ensure_user_plan_tier_column():
    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS plan_tier VARCHAR DEFAULT 'free'"))
            conn.execute(text("UPDATE users SET plan_tier='free' WHERE plan_tier IS NULL"))
    except Exception as e:
        print("⚠️ Could not ensure plan_tier column:", str(e))

@app.on_event("startup")
def on_startup():
    try:
        Base.metadata.create_all(bind=engine)
        print("✅ DB tables ensured")
        _ensure_user_plan_tier_column()
        print("✅ plan_tier ensured")
    except OperationalError as e:
        print("⚠️ DB not reachable on startup (local dev). App will still run.")
        print(e)

# ---------------- CORS ----------------

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
    allow_headers=["Authorization", "Content-Type", "Accept", "Origin", "X-Requested-With"],
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
      <p style="color:#6b7280;font-size:12px;">If you didn’t request this, you can ignore this email.</p>
      <p style="color:#6b7280;font-size:12px;">Or copy/paste this link:<br/><span>{reset_link}</span></p>
    </div>
    """

    try:
        r = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json={"from": FROM_EMAIL, "to": [to_email], "subject": subject, "html": html},
            timeout=10,
        )
        if r.status_code >= 300:
            print("⚠️ Resend email failed:", r.status_code, r.text)
            print("🔑 PASSWORD RESET LINK:", reset_link)
    except Exception as e:
        print("⚠️ Resend request error:", str(e))
        print("🔑 PASSWORD RESET LINK:", reset_link)

# ---------------- STRIPE ----------------

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "").strip()
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

PRO_MONTHLY_PRICE_ID      = "price_1Sz0cSLBOsv1gBi7yQoqTO0n"
PRO_YEARLY_PRICE_ID       = "price_1Sz0cTLBOsv1gBi7DKZyGbLy"
BUSINESS_MONTHLY_PRICE_ID = "price_1Sz0dZLBOsv1gBi7fqenphoj"
BUSINESS_YEARLY_PRICE_ID  = "price_1Sz0dZLBOsv1gBi72C7VtbH8"

ALLOWED_PRICE_IDS = {
    PRO_MONTHLY_PRICE_ID,
    PRO_YEARLY_PRICE_ID,
    BUSINESS_MONTHLY_PRICE_ID,
    BUSINESS_YEARLY_PRICE_ID,
}

def tier_from_price_id(price_id: str | None) -> str:
    if not price_id:
        return "free"
    if price_id in (BUSINESS_MONTHLY_PRICE_ID, BUSINESS_YEARLY_PRICE_ID):
        return "business"
    if price_id in (PRO_MONTHLY_PRICE_ID, PRO_YEARLY_PRICE_ID):
        return "pro"
    return "free"

def set_user_paid_and_tier(user: User, paid: bool, tier: str | None):
    user.is_paid = paid
    if paid:
        user.plan_tier = tier if tier in ("pro", "business") else "pro"
    else:
        user.plan_tier = "free"

def sync_user_tier_from_stripe_email(email: str) -> tuple[bool, str]:
    """
    Returns (paid, tier) based on Stripe active subscription for this email.
    """
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe not configured")

    # Find customer by email
    customers = stripe.Customer.list(email=email, limit=10)
    custs = customers.get("data") or []
    if not custs:
        return (False, "free")

    # Pick the newest customer
    custs.sort(key=lambda c: c.get("created", 0), reverse=True)
    customer_id = custs[0]["id"]

    # Find active subscription
    subs = stripe.Subscription.list(customer=customer_id, status="active", limit=10)
    data = subs.get("data") or []
    if not data:
        return (False, "free")

    # Pick newest active sub
    data.sort(key=lambda s: s.get("created", 0), reverse=True)
    sub = data[0]

    # Get first price on subscription items
    items = (sub.get("items") or {}).get("data") or []
    price_id = None
    if items:
        price_id = ((items[0].get("price") or {}).get("id"))

    tier = tier_from_price_id(price_id)
    return (True, tier)

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

class CheckoutBody(BaseModel):
    price_id: str

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
        plan_tier="free",
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
        "plan_tier": getattr(user, "plan_tier", "free"),
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
        "plan_tier": getattr(current_user, "plan_tier", "free"),
    }

# ---------------- BILLING ----------------

@app.post("/billing/checkout")
def billing_checkout(
    body: CheckoutBody,
    current_user: User = Depends(get_current_user),
):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe not configured")

    if body.price_id not in ALLOWED_PRICE_IDS:
        raise HTTPException(status_code=400, detail="Invalid price")

    success_url = f"{FRONTEND_URL}/billing/success?session_id={{CHECKOUT_SESSION_ID}}"
    cancel_url = f"{FRONTEND_URL}/billing/cancel"

    tier = tier_from_price_id(body.price_id)

    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            customer_email=current_user.email,
            line_items=[{"price": body.price_id, "quantity": 1}],
            success_url=success_url,
            cancel_url=cancel_url,
            subscription_data={
                "metadata": {
                    "user_id": str(current_user.id),
                    "email": current_user.email,
                    "plan_tier": tier,
                    "price_id": body.price_id,
                }
            },
            metadata={
                "user_id": str(current_user.id),
                "email": current_user.email,
                "plan_tier": tier,
                "price_id": body.price_id,
            },
        )
        return {"url": session.url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/billing/verify")
def billing_verify(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe not configured")

    try:
        s = stripe.checkout.Session.retrieve(session_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid session: {str(e)}")

    meta = s.get("metadata") or {}
    meta_user_id = meta.get("user_id")

    if meta_user_id and str(current_user.id) != str(meta_user_id):
        raise HTTPException(status_code=403, detail="Session does not belong to user")

    # If verify says paid, set paid+tier
    payment_status = s.get("payment_status")
    status = s.get("status")
    mode = s.get("mode")

    paid_ok = (payment_status == "paid") or (mode == "subscription" and status in ("complete", "completed"))

    if paid_ok:
        # Determine tier reliably
        tier = meta.get("plan_tier") or tier_from_price_id(meta.get("price_id"))

        # If still unknown, fallback to Stripe email lookup
        if tier == "free":
            paid2, tier2 = sync_user_tier_from_stripe_email(current_user.email)
            if paid2:
                tier = tier2

        set_user_paid_and_tier(current_user, True, tier)
        db.commit()
        db.refresh(current_user)

    return {"ok": True, "is_paid": current_user.is_paid, "plan_tier": getattr(current_user, "plan_tier", "free")}

@app.get("/billing/sync")
def billing_sync(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    ✅ FIXES YOUR EXACT PROBLEM:
    If you're already paid but plan_tier stayed "free", this will sync from Stripe.
    """
    paid, tier = sync_user_tier_from_stripe_email(current_user.email)

    if not paid:
        set_user_paid_and_tier(current_user, False, None)
    else:
        set_user_paid_and_tier(current_user, True, tier)

    db.commit()
    db.refresh(current_user)

    return {"ok": True, "is_paid": current_user.is_paid, "plan_tier": current_user.plan_tier}

@app.post("/billing/webhook")
async def billing_webhook(request: Request, db: Session = Depends(get_db)):
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="Stripe webhook not configured")

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(payload=payload, sig_header=sig_header, secret=STRIPE_WEBHOOK_SECRET)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    event_type = event.get("type")
    obj = event.get("data", {}).get("object", {})
    print("✅ Stripe webhook received:", event_type)

    def set_by_user_id(user_id: str | None, paid: bool, tier: str | None) -> bool:
        if not user_id:
            return False
        user = db.query(User).filter(User.id == int(user_id)).first()
        if not user:
            return False
        set_user_paid_and_tier(user, paid, tier)
        db.commit()
        return True

    def set_by_email(email: str | None, paid: bool, tier: str | None) -> bool:
        if not email:
            return False
        user = db.query(User).filter(User.email == email.lower().strip()).first()
        if not user:
            return False
        set_user_paid_and_tier(user, paid, tier)
        db.commit()
        return True

    if event_type == "checkout.session.completed":
        meta = (obj.get("metadata") or {})
        user_id = meta.get("user_id")
        tier = meta.get("plan_tier") or tier_from_price_id(meta.get("price_id"))
        email = (obj.get("customer_details") or {}).get("email") or obj.get("customer_email") or meta.get("email")

        if not set_by_user_id(user_id, True, tier):
            set_by_email(email, True, tier)

    if event_type in ("invoice.paid", "invoice.payment_succeeded"):
        invoice = obj
        subscription_id = invoice.get("subscription")
        customer_id = invoice.get("customer")

        user_id = None
        tier = None
        email = None

        if subscription_id:
            try:
                sub = stripe.Subscription.retrieve(subscription_id)
                smeta = sub.get("metadata") or {}
                user_id = smeta.get("user_id")
                tier = smeta.get("plan_tier") or tier_from_price_id(smeta.get("price_id"))
            except Exception as e:
                print("⚠️ Subscription retrieve failed:", str(e))

        if customer_id:
            try:
                cust = stripe.Customer.retrieve(customer_id)
                email = cust.get("email")
            except Exception as e:
                print("⚠️ Customer retrieve failed:", str(e))

        if not set_by_user_id(user_id, True, tier):
            set_by_email(email, True, tier)

    if event_type == "customer.subscription.deleted":
        meta = (obj.get("metadata") or {})
        user_id = meta.get("user_id")
        customer_id = obj.get("customer")

        email = None
        if customer_id:
            try:
                cust = stripe.Customer.retrieve(customer_id)
                email = cust.get("email")
            except Exception as e:
                print("⚠️ Customer retrieve failed:", str(e))

        if not set_by_user_id(user_id, False, None):
            set_by_email(email, False, None)

    return {"ok": True}

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
