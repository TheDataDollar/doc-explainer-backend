from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from deps import get_db
from models_affiliate import AffiliateAccount
from models_affiliate_tracking import AffiliateReferral

router = APIRouter(prefix="/affiliate", tags=["Affiliate Attribution"])


class AttachReferralIn(BaseModel):
    referred_user_id: int
    affiliate_ref_code: str


@router.post("/attach-referral")
def attach_referral(payload: AttachReferralIn, db: Session = Depends(get_db)):
    code = (payload.affiliate_ref_code or "").strip().upper()
    if not code:
        raise HTTPException(status_code=400, detail="Missing affiliate_ref_code")

    aff = (
        db.query(AffiliateAccount)
        .filter(AffiliateAccount.ref_code == code)
        .filter(AffiliateAccount.status == "approved")
        .first()
    )
    if not aff:
        raise HTTPException(status_code=404, detail="Affiliate not found or not approved")

    # Prevent duplicates: one user can only be referred once
    existing = (
        db.query(AffiliateReferral)
        .filter(AffiliateReferral.referred_user_id == payload.referred_user_id)
        .first()
    )
    if existing:
        return {"ok": True, "message": "Referral already attached"}

    db.add(
        AffiliateReferral(
            affiliate_id=aff.id,
            referred_user_id=payload.referred_user_id,
        )
    )
    db.commit()

    return {"ok": True}
