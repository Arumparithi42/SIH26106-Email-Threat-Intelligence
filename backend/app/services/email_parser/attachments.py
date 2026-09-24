"""Static attachment analysis. Attachments are NEVER written to disk, opened or executed.

We only look at: name, declared MIME type, size, SHA-256 and the first bytes
("magic number") to spot a type that disagrees with the extension.
"""
from __future__ import annotations

import mimetypes
from pathlib import PurePosixPath

from app.core.utils import sha256_hex

EXECUTABLE = {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".msi", ".dll", ".cpl", ".jar", ".app", ".elf"}
SCRIPT = {".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".hta", ".lnk", ".sh", ".py", ".reg"}
MACRO = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam", ".sldm"}
ARCHIVE_DISK = {".zip", ".rar", ".7z", ".iso", ".img", ".vhd", ".gz", ".tar", ".ace", ".cab"}
DOCUMENT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".rtf", ".odt", ".png", ".jpg", ".jpeg", ".gif"}

MAGIC = [
    (b"MZ", "windows_executable"),
    (b"\x7fELF", "elf_executable"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip_container"),  # zip, docx, xlsx, jar ...
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole_container"),  # legacy office
    (b"Rar!", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x89PNG", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF8", "gif"),
]
EXPECTED_MAGIC = {
    ".pdf": {"pdf"}, ".docx": {"zip_container"}, ".xlsx": {"zip_container"}, ".pptx": {"zip_container"},
    ".docm": {"zip_container"}, ".xlsm": {"zip_container"}, ".zip": {"zip_container"}, ".jar": {"zip_container"},
    ".doc": {"ole_container"}, ".xls": {"ole_container"}, ".ppt": {"ole_container"}, ".png": {"png"},
    ".jpg": {"jpeg"}, ".jpeg": {"jpeg"}, ".gif": {"gif"}, ".exe": {"windows_executable"}, ".dll": {"windows_executable"},
    ".rar": {"rar"}, ".7z": {"7z"},
}


def _detect_magic(payload: bytes) -> str | None:
    for sig, name in MAGIC:
        if payload.startswith(sig):
            return name
    return None


def analyze_attachment(filename: str | None, declared_mime: str, payload: bytes) -> dict:
    name = filename or "(unnamed)"
    has_rtlo = "‮" in name
    clean_name = name.replace("‮", "")
    suffixes = [s.lower() for s in PurePosixPath(clean_name).suffixes]
    ext = suffixes[-1] if suffixes else ""
    magic = _detect_magic(payload)
    guessed_mime = mimetypes.guess_type(clean_name)[0]

    flags: list[dict] = []

    def flag(code: str, severity: str, text: str) -> None:
        flags.append({"code": code, "severity": severity, "description": text})

    if ext in EXECUTABLE or magic in ("windows_executable", "elf_executable"):
        flag("executable", "high", f"Executable content ({ext or magic}) can run code when opened")
    if ext in SCRIPT:
        flag("script", "high", f"Script file ({ext}) can run code when double-clicked")
    if ext in MACRO:
        flag("macro_enabled", "medium", f"Macro-enabled Office document ({ext}) can contain VBA macros")
    if ext in ARCHIVE_DISK:
        flag("archive_or_disk_image", "low", f"Archive/disk image ({ext}) can hide other files from mail filters")
    if len(suffixes) >= 2 and suffixes[-2] in DOCUMENT and (ext in EXECUTABLE or ext in SCRIPT):
        flag("double_extension", "high", f"Double extension '{''.join(suffixes[-2:])}' disguises the real file type")
    if has_rtlo:
        flag("rtlo_character", "high", "Filename contains a right-to-left override character used to disguise extensions")
    expected = EXPECTED_MAGIC.get(ext)
    if expected and magic and magic not in expected:
        flag("content_extension_mismatch", "medium", f"File content looks like '{magic}' but extension is '{ext}'")
    if guessed_mime and declared_mime not in (guessed_mime, "application/octet-stream") and ext not in (".eml",):
        flag("mime_extension_mismatch", "low", f"Declared MIME '{declared_mime}' differs from expected '{guessed_mime}'")

    return {
        "filename": name,
        "extension": ext or None,
        "declared_mime": declared_mime,
        "expected_mime": guessed_mime,
        "detected_magic": magic,
        "size_bytes": len(payload),
        "sha256": sha256_hex(payload),
        "flags": flags,
        "executed": False,
        "note": "Static metadata only; the attachment was never opened, saved or executed.",
    }


def attachment_findings(attachments: list[dict]) -> list:
    """One finding per flag type (aggregated across attachments)."""
    from app.services.findings import ev, finding

    by_code: dict[str, list[tuple[dict, dict]]] = {}
    for att in attachments:
        for fl in att["flags"]:
            by_code.setdefault(fl["code"], []).append((att, fl))
    out = []
    for code, items in by_code.items():
        sev = items[0][1]["severity"]
        out.append(finding(
            f"F-ATT-{code.upper().replace('_', '-')}", category="attachment", severity=sev,
            confidence="high" if code in ("double_extension", "rtlo_character", "executable") else "medium",
            title=items[0][1]["description"].split(" (")[0] if code != "double_extension" else "Attachment uses a double extension",
            description="; ".join(f"{a['filename']}: {fl['description']}" for a, fl in items),
            why="File types that can run code, or names disguising their real type, are a common malware delivery method. This is static metadata only; the file was not executed.",
            evidence=[ev("attachment", {"filename": a["filename"], "sha256": a["sha256"], "size_bytes": a["size_bytes"], "declared_mime": a["declared_mime"]}, "MIME part")
                      for a, _ in items],
            sources=["attachment_analysis"], related=[f"file:{a['sha256']}" for a, _ in items], module="email_parser",
            finding_type="observed_fact"))
    return out
