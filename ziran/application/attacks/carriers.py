"""Carrier files for indirect prompt injection (spec 112), built with the standard library.

Each builder hides :attr:`Carrier.text` in a file a person reads as :attr:`Carrier.cover`:
white 1-point text in a PDF or DOCX, an off-screen HTML block, faint PNG pixels, or (with
``placement: metadata``) the file's metadata. Text is escaped for the format it lands in.
"""

from __future__ import annotations

import html
import io
import struct
import textwrap
import zipfile
import zlib
from typing import TYPE_CHECKING
from xml.sax.saxutils import escape

from ziran.domain.interfaces.adapter import Attachment

if TYPE_CHECKING:
    from ziran.domain.entities.attack import Carrier

MEDIA_TYPES = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "html": "text/html",
    "png": "image/png",
}


def build(carrier: Carrier) -> Attachment:
    """The carrier's file, named ``<name>.<format>``. Deterministic."""
    data = _BUILDERS[carrier.format](carrier)
    name = f"{carrier.name}.{carrier.format}"
    return Attachment(filename=name, media_type=MEDIA_TYPES[carrier.format], data=data)


def _wrap(text: str, width: int) -> list[str]:
    return [line for p in text.split("\n") for line in (textwrap.wrap(p, width) or [""])]


# ── PDF: one page, Helvetica, offsets computed ───────────────────────


def _pdf_str(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").replace("\n", "\\n")


def _pdf_text(text: str, width: int, size: str, lead: str, y: int, colour: str = "") -> str:
    rows = "".join(f"({_pdf_str(t)}) Tj T*\n" for t in _wrap(text, width))
    return f"BT {colour}/F1 {size} Tf {lead} TL 72 {y} Td\n{rows}ET\n"


def _pdf(c: Carrier) -> bytes:
    stream = _pdf_text(c.cover, 90, "11", "14", 720)
    if c.placement == "body":  # white on white, 1 point: invisible, still extracted
        stream += _pdf_text(c.text, 200, "1", "1.2", 60, "1 1 1 rg ")
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        "/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        f"<< /Length {len(stream)} >>\nstream\n{stream}endstream",
    ]
    info = ""
    if c.placement == "metadata":
        objects.append(f"<< /Title ({_pdf_str(c.name)}) /Subject ({_pdf_str(c.text)}) >>")
        info = " /Info 6 0 R"
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for n, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{n} 0 obj\n{body}\nendobj\n".encode()
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    out += "".join(f"{o:010d} 00000 n \n" for o in offsets).encode()
    trailer = f"<< /Size {len(objects) + 1} /Root 1 0 R{info} >>"
    out += f"trailer\n{trailer}\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


# ── DOCX: the four parts Word needs ──────────────────────────────────

_XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
_PKG = "http://schemas.openxmlformats.org/package/2006"
_DOC_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
_DOCX_TYPES = (
    f'{_XML}<Types xmlns="{_PKG}/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    f'<Override PartName="/word/document.xml" ContentType="{_DOC_TYPE}"/>'
    '<Override PartName="/docProps/core.xml" '
    'ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>'
)
_DOCX_RELS = (
    f'{_XML}<Relationships xmlns="{_PKG}/relationships">'
    '<Relationship Id="rId1" Target="word/document.xml" Type="http://schemas.openxmlformats.org/'
    'officeDocument/2006/relationships/officeDocument"/>'
    f'<Relationship Id="rId2" Target="docProps/core.xml" Type="{_PKG}/relationships/metadata/'
    'core-properties"/></Relationships>'
)


def _run(text: str, props: str = "") -> str:
    return f'<w:p><w:r>{props}<w:t xml:space="preserve">{escape(text)}</w:t></w:r></w:p>'


def _docx(c: Carrier) -> bytes:
    body = "".join(_run(line) for line in c.cover.split("\n"))
    description = ""
    if c.placement == "body":  # a white 1-point run
        body += _run(c.text, '<w:rPr><w:color w:val="FFFFFF"/><w:sz w:val="2"/></w:rPr>')
    else:
        description = f"<dc:description>{escape(c.text)}</dc:description>"
    w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    parts = {
        "[Content_Types].xml": _DOCX_TYPES,
        "_rels/.rels": _DOCX_RELS,
        "word/document.xml": f'{_XML}<w:document xmlns:w="{w}"><w:body>{body}</w:body></w:document>',
        "docProps/core.xml": f'{_XML}<cp:coreProperties xmlns:cp="{_PKG}/metadata/core-properties"'
        f' xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>{escape(c.name)}</dc:title>'
        f"{description}</cp:coreProperties>",
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as z:
        for name, text in parts.items():  # a fixed timestamp keeps the bytes stable
            z.writestr(zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)), text, zipfile.ZIP_DEFLATED)
    return buffer.getvalue()


# ── HTML ─────────────────────────────────────────────────────────────


def _html(c: Carrier) -> bytes:
    e = html.escape
    meta = hidden = ""
    if c.placement == "body":
        style = "position:absolute;left:-9999px;top:-9999px"
        hidden = f'<div style="{style}" aria-hidden="true">{e(c.text)}</div>'
    else:
        meta = f'<meta name="description" content="{e(c.text)}">'
    paras = "".join(f"<p>{e(line)}</p>" for line in c.cover.split("\n"))
    head = f'<meta charset="utf-8"><title>{e(c.name)}</title>{meta}'
    return (
        f"<!doctype html>\n<html><head>{head}</head><body>{paras}{hidden}</body></html>\n".encode()
    )


# ── PNG: 8-bit grey, a 5x7 bitmap font at twice its size ─────────────

# Each glyph is its character, then seven rows of five pixels, one base-32 digit per row.
_GLYPHS = (
    "AEHHVHHH BUHHUHHU CEHGGGHE DUHHHHHU EVGGUGGV FVGGUGGG GEHGNHHF HHHHVHHH IE44444E "
    "J72222IC KHIKOKIH LGGGGGGV MHRLLHHH NHHPLJHH OEHHHHHE PUHHUGGG QEHHHLID RUHHUKIH "
    "SFGGE11U TV444444 UHHHHHHE VHHHHHA4 WHHHLLLA XHHA4AHH YHHA4444 ZV1248GV 0EHJLPHE "
    "14C4444E 2EH1248V 3V2421HE 426AIV22 5VGU11HE 668GUHHE 7V124888 8EHHEHHE 9EHHF12C "
    ".00000CC ,0000C48 :0CC0CC0 !4444404 ?EH12404 -000V000 _000000V /01248G0 @EHNLNGE "
    "'4480000 (2488842 )8422248 =00V0V00"
)
_FONT = {g[0]: [int(row, 32) for row in g[1:]] for g in _GLYPHS.split()}
_SCALE, _COLS, _MARGIN = 2, 60, 16
_COVER_INK, _FAINT_INK = 0x20, 0xB4  # the injection is faint grey: easy for a person to miss


def _chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def _png(c: Carrier) -> bytes:
    lines = [(t, _COVER_INK) for t in _wrap(c.cover, _COLS)]
    if c.placement == "body":
        lines += [("", _COVER_INK)] + [(t, _FAINT_INK) for t in _wrap(c.text, _COLS)]
    width = 2 * _MARGIN + _COLS * 6 * _SCALE
    blank = b"\x00" + b"\xff" * width  # each scanline starts with filter type 0
    rows = [blank] * _MARGIN
    for text, ink in lines:
        for y in range(8):
            row = bytearray(blank)
            for i, ch in enumerate(text.upper()):
                bits = _FONT[ch][y] if ch in _FONT and y < 7 else 0
                for x in range(5):
                    if bits >> (4 - x) & 1:
                        start = 1 + _MARGIN + (i * 6 + x) * _SCALE
                        row[start : start + _SCALE] = bytes((ink,)) * _SCALE
            rows += [bytes(row)] * _SCALE
    rows += [blank] * _MARGIN
    header = struct.pack(">IIBBBBB", width, len(rows), 8, 0, 0, 0, 0)
    meta = b"" if c.placement == "body" else _chunk(b"tEXt", b"Description\x00" + c.text.encode())
    idat = _chunk(b"IDAT", zlib.compress(b"".join(rows)))
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", header) + meta + idat + _chunk(b"IEND", b"")


_BUILDERS = {"pdf": _pdf, "docx": _docx, "html": _html, "png": _png}
