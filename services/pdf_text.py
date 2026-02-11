from __future__ import annotations

import os


def extract_text_from_pdf_path(pdf_path: str) -> str:
    """
    Baby-simple PDF text extraction.
    Input: path to a PDF on disk
    Output: best-effort plain text
    """
    if not pdf_path or not os.path.exists(pdf_path):
        return ""

    # Option A (best): pdfplumber
    try:
        import pdfplumber  # pip install pdfplumber
        chunks: list[str] = []
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                t = page.extract_text() or ""
                if t.strip():
                    chunks.append(t)
        return "\n\n".join(chunks).strip()
    except Exception:
        pass

    # Option B: PyPDF2 fallback
    try:
        from PyPDF2 import PdfReader  # pip install PyPDF2
        reader = PdfReader(pdf_path)
        chunks: list[str] = []
        for page in reader.pages:
            t = page.extract_text() or ""
            if t.strip():
                chunks.append(t)
        return "\n\n".join(chunks).strip()
    except Exception:
        return ""
