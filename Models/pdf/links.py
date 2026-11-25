"""Extract the web links embedded in a PDF (revision R8, link check).

Link-based phishing PDFs carry no script or automatic action; they lure the reader to a malicious web page.
The chatbot therefore extracts the http(s) links of each uploaded PDF and checks them with its URL detector.
Links are taken from link annotations (PyMuPDF) and, for malformed files, from /URI entries in the raw bytes.
"""
import re

MAX_LINKS = 5
_URI_RE = re.compile(rb'/URI\s*\((https?://[^)\s]{4,2000})\)', re.I)


def extract_links(path, max_links=MAX_LINKS):
    links = []
    try:
        try:
            import pymupdf
        except ImportError:
            import fitz as pymupdf
        with pymupdf.open(path) as doc:
            for page in doc:
                for l in page.get_links():
                    u = (l.get('uri') or '').strip()
                    if u.lower().startswith(('http://', 'https://')):
                        links.append(u)
    except Exception:
        pass
    if not links:
        try:
            with open(path, 'rb') as f:
                raw = f.read()
            links = [m.group(1).decode('latin-1') for m in _URI_RE.finditer(raw)]
        except Exception:
            pass
    seen, out = set(), []
    for u in links:  # distinct links, in order of appearance
        if u not in seen:
            seen.add(u); out.append(u)
        if len(out) >= max_links:
            break
    return out
