
"""Upload validation for Bayyina contracts."""
from __future__ import annotations

from dataclasses import dataclass
import re
import unicodedata
import uuid

MAX_BYTES = 25 * 1024 * 1024

CONTENT_TYPES = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}

SIGNATURES = {
    "pdf": b"%PDF-",
    "docx": b"PK\x03\x04",
}

BIDI_CONTROLS = {
    "\u061c", "\u200e", "\u200f",
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
}


class ValidationError(Exception):
    def __init__(self, errors: dict[str, str]):
        super().__init__(", ".join(sorted(errors)))
        self.errors = errors


@dataclass(frozen=True)
class CleanUpload:
    stored_name: str
    display_name: str
    extension: str
    content_type: str
    size_bytes: int
    matter_id: str


def validate_upload(meta: dict) -> CleanUpload:
    errors = {}

    raw_filename = meta.get("filename")
    display_name = None
    extension = None
    filename_valid = False

    if isinstance(raw_filename, str):
        display_name = unicodedata.normalize("NFC", raw_filename)

        valid_name = (
            1 <= len(display_name) <= 120
            and not any(unicodedata.category(ch) == "Cc" for ch in display_name)
            and not any(ch in BIDI_CONTROLS for ch in display_name)
            and "/" not in display_name
            and "\\" not in display_name
            and ".." not in display_name
            and not display_name.startswith(".")
        )

        if valid_name and "." in display_name:
            name_part, ext_part = display_name.rsplit(".", 1)
            candidate_extension = ext_part.lower()

            if name_part.strip() and candidate_extension in CONTENT_TYPES:
                extension = candidate_extension
                filename_valid = True

    if not filename_valid:
        errors["filename"] = "Invalid filename."

    content_type = meta.get("content_type")

    if not isinstance(content_type, str):
        errors["content_type"] = "Content type must be a string."
    elif filename_valid and content_type != CONTENT_TYPES[extension]:
        errors["content_type"] = "Content type does not match the extension."

    # 3. Validate file signature
    first_bytes = meta.get("first_bytes")

    if not isinstance(first_bytes, bytes):
        errors["first_bytes"] = "File signature must be bytes."
    elif filename_valid and not first_bytes.startswith(SIGNATURES[extension]):
        errors["first_bytes"] = "File signature does not match the extension."

    size_bytes = meta.get("size_bytes")

    if (
        not isinstance(size_bytes, int)
        or isinstance(size_bytes, bool)
        or not 1 <= size_bytes <= MAX_BYTES
    ):
        errors["size_bytes"] = "Invalid file size."

    matter_id = meta.get("matter_id")

    if (
        not isinstance(matter_id, str)
        or re.fullmatch(r"MAT-[0-9]{4}-[0-9]{5}", matter_id, flags=re.ASCII) is None
    ):
        errors["matter_id"] = "Invalid matter ID."

    # Report all errors together
    if errors:
        raise ValidationError(errors)

    return CleanUpload(
        stored_name=f"{uuid.uuid4().hex}.{extension}",
        display_name=display_name,
        extension=extension,
        content_type=CONTENT_TYPES[extension],
        size_bytes=size_bytes,
        matter_id=matter_id,
    )
