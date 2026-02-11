from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, BigInteger, func
from db import Base  # ✅ <-- CHANGE THIS to match your project

class AffiliateClick(Base):
    __tablename__ = "affiliate_clicks"
    id = Column(Integer, primary_key=True, index=True)
    affiliate_id = Column(Integer, ForeignKey("affiliate_accounts.id"), index=True, nullable=False)
    landing_path = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class AffiliateReferral(Base):
    __tablename__ = "affiliate_referrals"
    id = Column(Integer, primary_key=True, index=True)
    affiliate_id = Column(Integer, ForeignKey("affiliate_accounts.id"), index=True, nullable=False)
    referred_user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)  # adjust if needed
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    first_paid_at = Column(DateTime(timezone=True), nullable=True)

class AffiliateCommissionLedger(Base):
    __tablename__ = "affiliate_commission_ledger"
    id = Column(Integer, primary_key=True, index=True)
    affiliate_id = Column(Integer, ForeignKey("affiliate_accounts.id"), index=True, nullable=False)
    referral_id = Column(Integer, ForeignKey("affiliate_referrals.id"), index=True, nullable=False)
    stripe_invoice_id = Column(String, unique=True, index=True, nullable=False)
    amount_cents = Column(BigInteger, nullable=False)
    currency = Column(String, default="usd", nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
