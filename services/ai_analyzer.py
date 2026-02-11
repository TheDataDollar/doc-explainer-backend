import os
from openai import OpenAI

# Create OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """
You are a real estate document expert.

Your job:
- Explain documents in plain English
- Highlight fees, deadlines, penalties
- Identify risks and red flags
- Call out sneaky clauses that people miss
- Be clear, structured, and professional

Do NOT give legal advice.
"""

def analyze_document_text(text: str) -> str:
    """
    Takes extracted document text and returns a structured explanation.
    """
    if not text.strip():
        return "No readable text was found in this document."

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"""
Explain the following real estate document.

Structure your response with:
1. Plain-English Summary
2. Key Fees & Costs
3. Important Dates & Deadlines
4. Red Flags & Risks
5. Questions to Ask Before Signing

DOCUMENT:
{text}
"""
            }
        ],
        temperature=0.2,
        max_tokens=1200,
    )

    return response.choices[0].message.content.strip()
