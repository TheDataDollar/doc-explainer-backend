from sqlalchemy import Column, Integer, String, Float, DateTime, func
from db import Base  # ✅ keep this if your project has db.py with Base

class AffiliateAccount(Base):
    __tablename__ = "affiliate_accounts"

    id = Column(Integer, primary_key=True, index=True)

    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)

    display_name = Column(String, nullable=True)

    # "pending" | "approved"
    status = Column(String, default="pending", nullable=False)

    # unique referral code
    ref_code = Column(String, unique=True, index=True, nullable=False)

    # commission rate like 0.30
    commission_rate = Column(Float, default=0.30, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
