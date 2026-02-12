from __future__ import annotations

import os

def extract_text_from_pdf_path(pdf_path: str) -> str:
    """
    Baby-simple PDF text extraction with OCR fallback.
    Input: path to a PDF on disk
    Output: best-effort plain text
    """
    if not pdf_path or not os.path.exists(pdf_path):
        return ""

    # -----------------------
    # Option A (best): pdfplumber
    # -----------------------
    try:
        import pdfplumber  # pip install pdfplumber
        chunks: list[str] = []
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                t = page.extract_text() or ""
                if t.strip():
                    chunks.append(t)
        text = "\n\n".join(chunks).strip()
        if text:
            return text
    except Exception:
        pass

    # -----------------------
    # Option B: PyPDF2 fallback
    # -----------------------
    try:
        from PyPDF2 import PdfReader  # pip install PyPDF2
        reader = PdfReader(pdf_path)
        chunks: list[str] = []
        for page in reader.pages:
            t = page.extract_text() or ""
            if t.strip():
                chunks.append(t)
        text = "\n\n".join(chunks).strip()
        if text:
            return text
    except Exception:
        pass

    # -----------------------
    # Option C: OCR fallback (scanned/image PDFs)
    # Uses pypdfium2 to render pages -> pytesseract to read text
    # -----------------------
    try:
        import pytesseract  # pip install pytesseract
        import pypdfium2 as pdfium  # already in your env earlier
        from PIL import Image  # pillow is already in your env

        doc = pdfium.PdfDocument(pdf_path)
        out: list[str] = []

        # Render a limited number of pages if you want (uncomment to limit)
        # max_pages = min(len(doc), 15)
        # page_range = range(max_pages)

        page_range = range(len(doc))

        for i in page_range:
            page = doc[i]
            # 2.0 scale = clearer OCR without being insane
            bitmap = page.render(scale=2.0)
            pil_image: Image.Image = bitmap.to_pil()

            txt = pytesseract.image_to_string(pil_image, lang="eng") or ""
            if txt.strip():
                out.append(txt.strip())

        return "\n\n".join(out).strip()
    except Exception:
        return ""
