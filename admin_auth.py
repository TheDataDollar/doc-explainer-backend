import os
from fastapi import Header, HTTPException

def require_admin(x_admin_key: str | None = Header(default=None)) -> None:
    expected = os.getenv("ADMIN_KEY", "")
    if not expected:
        raise HTTPException(status_code=500, detail="ADMIN_KEY not set")

    if not x_admin_key or x_admin_key != expected:
        raise HTTPException(status_code=401, detail="Invalid admin key")
