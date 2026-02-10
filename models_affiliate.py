# models_affiliate.py (FULL COPY / REPLACE)

from sqlalchemy import Column, Integer, String, DateTime, Float, func
from db import Base


class AffiliateAccount(Base):
    __tablename__ = "affiliate_accounts"

    id = Column(Integer, primary_key=True, index=True)

    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)

    display_name = Column(String, nullable=True)
    status = Column(String, default="pending", nullable=False)

    ref_code = Column(String, unique=True, index=True, nullable=False)
    commission_rate = Column(Float, default=0.30, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
