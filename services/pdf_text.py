from __future__ import annotations

import os

def extract_text_from_pdf_path(pdf_path: str) -> str:
    """
    Best-effort PDF text extraction:
    1) pdfplumber (text PDFs)
    2) PyPDF2 (fallback)
    3) OCR fallback (scanned PDFs) using pdf2image + pytesseract
       (requires system deps on server: tesseract + poppler)
    """
    if not pdf_path or not os.path.exists(pdf_path):
        return ""

    # ---------- A) pdfplumber ----------
    try:
        import pdfplumber
        chunks: list[str] = []
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                t = page.extract_text() or ""
                t = t.strip()
                if t:
                    chunks.append(t)
        text = "\n\n".join(chunks).strip()
        if text:
            return text
    except Exception:
        pass

    # ---------- B) PyPDF2 ----------
    try:
        from PyPDF2 import PdfReader
        reader = PdfReader(pdf_path)
        chunks: list[str] = []
        for page in reader.pages:
            t = page.extract_text() or ""
            t = t.strip()
            if t:
                chunks.append(t)
        text = "\n\n".join(chunks).strip()
        if text:
            return text
    except Exception:
        pass

    # ---------- C) OCR fallback ----------
    try:
        # Converts PDF pages -> images, then OCR images -> text
        from pdf2image import convert_from_path
        import pytesseract

        # Convert first N pages to keep costs controlled
        MAX_PAGES = 12
        images = convert_from_path(pdf_path, dpi=250, first_page=1, last_page=MAX_PAGES)

        ocr_chunks: list[str] = []
        for img in images:
            t = pytesseract.image_to_string(img) or ""
            t = t.strip()
            if t:
                ocr_chunks.append(t)

        return "\n\n".join(ocr_chunks).strip()
    except Exception:
        return ""
