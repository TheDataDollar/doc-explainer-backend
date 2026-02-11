from fastapi import APIRouter, HTTPException
import os

from openai import OpenAI

router = APIRouter(prefix="/ai", tags=["AI"])

@router.get("/health")
def ai_health():
    key = (os.getenv("OPENAI_API_KEY") or "").strip()
    if not key:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY not set on server")

    client = OpenAI(api_key=key)

    try:
        resp = client.responses.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            input="Reply with exactly: ok",
        )
        return {"ok": True, "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"), "reply": resp.output_text.strip()}
    except Exception as e:
        # Most common cause: no API billing / invalid key
        raise HTTPException(status_code=500, detail=f"OpenAI call failed: {str(e)}")
