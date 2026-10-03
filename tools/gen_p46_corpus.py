#!/usr/bin/env python3
"""Phase 46 corpus — ZIP-family members that trigger upstream
NFD_ZIP member handlers (handle_Microsoftoffice/handle_OpenOffice).

Fixtures (written to corpus/):
  office-docx.zip    docProps/app.xml "Microsoft Office Word" + AppVersion
  office-xlsx.zip    "Microsoft Excel"
  office-sheetjs.zip "SheetJS" (maps to Excel + sInfo=SheetJS)
  office-plain.zip   app.xml with unknown <Application> -> MICROSOFTOFFICE
  office-noapp.zip   app.xml without <Application> -> MICROSOFTOFFICE
  office-big.zip     app.xml uncompressed > 0x4000 -> gate fails, no record
  office-empty.zip   app.xml empty member -> gate fails, no record
  office-stored.zip  app.xml stored (method 0) instead of deflate
  odt.zip            meta.xml containing ":opendocument:" -> OPENDOCUMENT
  odt-plain.zip      meta.xml without the marker -> no record

All members are tiny synthetic XML; nothing here is a real document.
"""

import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "corpus"

APP_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
    '<Application>{app}</Application><AppVersion>{ver}</AppVersion>'
    '</Properties>'
)

META_ODT = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<office:document-meta '
    'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
    'xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0">'
    '<office:meta><meta:generator>Phase46Fixture/1.0</meta:generator></office:meta>'
    '</office:document-meta>'
)

META_PLAIN = '<?xml version="1.0"?><meta><generator>x</generator></meta>'


def make(path: Path, entries: list[tuple[str, bytes, int]]) -> None:
    with zipfile.ZipFile(path, "w") as z:
        for name, data, method in entries:
            zi = zipfile.ZipInfo(name)
            zi.compress_type = method
            z.writestr(zi, data)
    print(f"wrote {path.name} ({path.stat().st_size}B)")


def main() -> int:
    D = zipfile.ZIP_DEFLATED
    S = zipfile.ZIP_STORED
    make(CORPUS / "office-docx.zip", [
        ("docProps/app.xml", APP_XML.format(app="Microsoft Office Word", ver="16.0000").encode(), D),
        ("word/document.xml", b"<w:document/>", D),
    ])
    make(CORPUS / "office-xlsx.zip", [
        ("docProps/app.xml", APP_XML.format(app="Microsoft Excel", ver="12.0").encode(), D),
        ("xl/workbook.xml", b"<workbook/>", D),
    ])
    make(CORPUS / "office-sheetjs.zip", [
        ("docProps/app.xml", APP_XML.format(app="SheetJS", ver="").encode(), D),
    ])
    make(CORPUS / "office-plain.zip", [
        ("docProps/app.xml", APP_XML.format(app="Contoso Writer", ver="9.9").encode(), D),
    ])
    make(CORPUS / "office-noapp.zip", [
        ("docProps/app.xml", b'<?xml version="1.0"?><Properties><AppVersion>7.7</AppVersion></Properties>', D),
    ])
    big = APP_XML.format(app="Microsoft Office Word", ver="16.0000") + (" " * 0x4100)
    make(CORPUS / "office-big.zip", [
        ("docProps/app.xml", big.encode(), D),
    ])
    make(CORPUS / "office-empty.zip", [
        ("docProps/app.xml", b"", D),
    ])
    make(CORPUS / "office-stored.zip", [
        ("docProps/app.xml", APP_XML.format(app="Microsoft Office Word", ver="16.0000").encode(), S),
    ])
    make(CORPUS / "odt.zip", [
        ("meta.xml", META_ODT.encode(), D),
        ("content.xml", b"<office:document-content/>", D),
    ])
    make(CORPUS / "odt-plain.zip", [
        ("meta.xml", META_PLAIN.encode(), D),
    ])
    return 0


if __name__ == "__main__":
    sys.exit(main())
