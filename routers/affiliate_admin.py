# routers/affiliate_admin.py

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from deps import get_db
from admin_auth import require_admin
from models_affiliate import AffiliateAccount

router = APIRouter(prefix="/affiliate/admin", tags=["Affiliate Admin"])


class ApproveAffiliateBody(BaseModel):
    email: EmailStr
    commission_rate: Optional[float] = 0.30


@router.get("/pending")
def list_pending_affiliates(
    db: Session = Depends(get_db),
    _admin=Depends(require_admin),
):
    rows = (
        db.query(AffiliateAccount)
        .filter(AffiliateAccount.status == "pending")
        .order_by(AffiliateAccount.id.desc())
        .all()
    )

    return [
        {
            "id": a.id,
            "email": a.email,
            "display_name": a.display_name,
            "status": a.status,
            "ref_code": a.ref_code,
            "commission_rate": a.commission_rate,
            "created_at": a.created_at,
        }
        for a in rows
    ]


@router.post("/approve")
def approve_affiliate(
    body: ApproveAffiliateBody,
    db: Session = Depends(get_db),
    _admin=Depends(require_admin),
):
    email = body.email.lower().strip()

    acc = db.query(AffiliateAccount).filter(AffiliateAccount.email == email).first()
    if not acc:
        raise HTTPException(status_code=404, detail="Affiliate not found")

    rate = float(body.commission_rate or 0.30)
    if rate <= 0 or rate > 1:
        raise HTTPException(status_code=400, detail="commission_rate must be between 0 and 1")

    acc.status = "approved"
    acc.commission_rate = rate

    db.commit()
    db.refresh(acc)

    return {
        "ok": True,
        "email": acc.email,
        "status": acc.status,
        "commission_rate": acc.commission_rate,
        "ref_code": acc.ref_code,
    }


@router.post("/reject")
def reject_affiliate(
    email: EmailStr,
    db: Session = Depends(get_db),
    _admin=Depends(require_admin),
):
    e = email.lower().strip()
    acc = db.query(AffiliateAccount).filter(AffiliateAccount.email == e).first()
    if not acc:
        raise HTTPException(status_code=404, detail="Affiliate not found")

    acc.status = "rejected"
    db.commit()

    return {"ok": True, "email": acc.email, "status": acc.status}
