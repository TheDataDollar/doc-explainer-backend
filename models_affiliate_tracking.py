from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, BigInteger, func
from database import Base  # ✅ change this import if your Base is elsewhere


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

    # ✅ IMPORTANT: change "users" if your main user table has a different name
    referred_user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    first_paid_at = Column(DateTime(timezone=True), nullable=True)


class AffiliateCommissionLedger(Base):
    __tablename__ = "affiliate_commission_ledger"

    id = Column(Integer, primary_key=True, index=True)
    affiliate_id = Column(Integer, ForeignKey("affiliate_accounts.id"), index=True, nullable=False)
    referral_id = Column(Integer, ForeignKey("affiliate_referrals.id"), index=True, nullable=False)

    stripe_invoice_id = Column(String, unique=True, index=True, nullable=False)

    amount_cents = Column(BigInteger, nullable=False)  # cents, exact integer math
    currency = Column(String, default="usd", nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
