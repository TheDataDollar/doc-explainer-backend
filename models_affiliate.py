# models_affiliate.py

from sqlalchemy import Column, Integer, String, DateTime, Float, func
from models import Base


class AffiliateAccount(Base):
    __tablename__ = "affiliate_accounts"

    id = Column(Integer, primary_key=True, index=True)

    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)

    display_name = Column(String, nullable=True)

    # pending | approved | rejected
    status = Column(String, default="pending", nullable=False)

    # e.g. A1B2C3D4
    ref_code = Column(String, unique=True, index=True, nullable=False)

    # 0.30 = 30%
    commission_rate = Column(Float, default=0.30, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
