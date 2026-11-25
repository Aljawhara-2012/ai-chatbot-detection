"""Runtime feature extractor for uploaded PDFs.

Computes the same 30 candidate features as the Evasive-PDFMal2022 dataset (PDFMalware2022.csv):
  - general features read with PyMuPDF: pdfsize (KB), metadata size, pages, xref Length, title characters,
    isEncrypted, embedded files, images, text (1 = contains text)
  - structural keyword counts in the raw file, pdfid-style (names are hex-decoded, so /J#61vaScript counts
    as /JavaScript): obj, endobj, stream, endstream, xref, trailer, startxref, pageno (/Page), encrypt,
    ObjStm, JS, Javascript, AA, OpenAction, Acroform, JBIG2Decode, RichMedia, launch, EmbeddedFile, XFA,
    Colors (/Colors values > 2^24)
Malformed files are not rejected: a feature that cannot be read is set to -1, as in the dataset.

Usage:  from pdf_features import extract_features;  feats = extract_features("file.pdf")  # dict
"""
import os, re

FEATURES = ['pdfsize', 'metadata size', 'pages', 'xref Length', 'title characters', 'isEncrypted', 'embedded files',
            'images', 'text', 'obj', 'endobj', 'stream', 'endstream', 'xref', 'trailer', 'startxref', 'pageno',
            'encrypt', 'ObjStm', 'JS', 'Javascript', 'AA', 'OpenAction', 'Acroform', 'JBIG2Decode', 'RichMedia',
            'launch', 'EmbeddedFile', 'XFA', 'Colors']

_KEYWORDS = {'obj': b'obj', 'endobj': b'endobj', 'stream': b'stream', 'endstream': b'endstream', 'xref': b'xref',
             'trailer': b'trailer', 'startxref': b'startxref'}
_NAMES = {'pageno': 'Page', 'encrypt': 'Encrypt', 'ObjStm': 'ObjStm', 'JS': 'JS', 'Javascript': 'JavaScript',
          'AA': 'AA', 'OpenAction': 'OpenAction', 'Acroform': 'AcroForm', 'JBIG2Decode': 'JBIG2Decode',
          'RichMedia': 'RichMedia', 'launch': 'Launch', 'EmbeddedFile': 'EmbeddedFile', 'XFA': 'XFA'}
_DELIM = rb'\s\(\)<>\[\]\{\}/%'
_NAME_RE = re.compile(rb'/([^' + _DELIM + rb']*)')
_HEX_RE = re.compile(rb'#([0-9A-Fa-f]{2})')


def _structural(raw: bytes) -> dict:
    out = {}
    for k, kw in _KEYWORDS.items():  # keywords delimited by whitespace / delimiters
        out[k] = len(re.findall(rb'(?<![^' + _DELIM + rb'])' + kw + rb'(?![^' + _DELIM + rb'])', raw))
    names = {}
    colors = 0
    for m in _NAME_RE.finditer(raw):
        n = _HEX_RE.sub(lambda h: bytes([int(h.group(1), 16)]), m.group(1)).decode('latin-1')
        names[n] = names.get(n, 0) + 1
        if n == 'Colors':
            v = re.match(rb'\s*(\d+)', raw[m.end():m.end() + 20])
            if v and int(v.group(1)) > 2 ** 24:
                colors += 1
    for k, n in _NAMES.items():
        out[k] = names.get(n, 0)
    out['Colors'] = colors
    return out


def _general(path: str) -> dict:
    g = {'metadata size': -1, 'pages': -1, 'xref Length': -1, 'title characters': -1, 'isEncrypted': 0,
         'embedded files': -1, 'images': -1, 'text': 0}
    try:
        import pymupdf
    except ImportError:  # older PyMuPDF
        import fitz as pymupdf
    try:
        doc = pymupdf.open(path)
    except Exception:
        return g
    with doc:
        g['isEncrypted'] = int(bool(doc.is_encrypted))
        try:
            md = doc.metadata or {}
            g['metadata size'] = len(str(md).encode())
            g['title characters'] = len(md.get('title') or '')
        except Exception:
            pass
        for key, fn in (('pages', lambda: doc.page_count), ('xref Length', lambda: doc.xref_length()),
                        ('embedded files', lambda: doc.embfile_count())):
            try:
                g[key] = int(fn())
            except Exception:
                pass
        try:
            imgs, has_text = 0, False
            for p in doc:
                imgs += len(p.get_images(full=True))
                if not has_text and p.get_text().strip():
                    has_text = True
            g['images'], g['text'] = imgs, int(has_text)
        except Exception:
            pass
    return g


def extract_features(path: str) -> dict:
    with open(path, 'rb') as f:
        raw = f.read()
    feats = {'pdfsize': os.path.getsize(path) / 1024.0}  # KB, the unit used in the training data
    feats.update(_general(path))
    feats.update(_structural(raw))
    return {k: float(feats[k]) for k in FEATURES}


if __name__ == '__main__':
    import sys, json
    for p in sys.argv[1:]:
        print(p, json.dumps(extract_features(p)))
