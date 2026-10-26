"""Input file validation, size enforcement, encoding detection, and format verification."""

from pathlib import Path
from typing import Literal
from tracehunt.config import settings
from tracehunt.exceptions import ValidationError

SupportedFormat = Literal["json", "jsonl", "csv"]


def detect_encoding(file_bytes: bytes) -> str:
    """Detect text encoding based on Byte Order Marks (BOM) or try UTF-8 / UTF-16."""
    if file_bytes.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if file_bytes.startswith(b"\xff\xfe"):
        return "utf-16-le"
    if file_bytes.startswith(b"\xfe\xff"):
        return "utf-16-be"

    # Try decoding small sample as UTF-8
    sample = file_bytes[:8192]
    try:
        sample.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError:
        pass

    try:
        sample.decode("utf-16")
        return "utf-16"
    except UnicodeDecodeError:
        pass

    # Fallback to latin-1
    return "latin-1"


def detect_file_format(content_str: str) -> SupportedFormat:
    """Inspect decoded content to identify whether it is a JSON array, JSONL, or CSV.

    Does not rely solely on file extensions.
    """
    stripped = content_str.strip()
    if not stripped:
        raise ValidationError("File content is empty")

    # 1. JSON Array check: starts with '[' and ends with ']'
    if stripped.startswith("[") and stripped.endswith("]"):
        return "json"

    # 2. JSON Lines check: first non-empty line starts with '{' and ends with '}'
    first_line = stripped.splitlines()[0].strip()
    if first_line.startswith("{") and first_line.endswith("}"):
        return "jsonl"

    # Single JSON object can also be treated as jsonl (single record)
    if stripped.startswith("{") and stripped.endswith("}"):
        return "jsonl"

    # 3. CSV Check: look for comma or semicolon delimited header
    if "," in first_line or ";" in first_line:
        return "csv"

    raise ValidationError(
        "Unsupported or unrecognized file format. Must be JSON array, JSON Lines, or CSV."
    )


def validate_input_file(file_path: Path | str) -> tuple[str, SupportedFormat]:
    """Validate file existence, check size constraints, and decode content.

    Returns:
        tuple[str, SupportedFormat]: Decoded text content and detected format.
    """
    path = Path(file_path)
    if not path.exists():
        raise ValidationError(f"File not found: {path}")

    if not path.is_file():
        raise ValidationError(f"Path is not a regular file: {path}")

    # Check size limit
    size_bytes = path.stat().st_size
    if size_bytes == 0:
        raise ValidationError(f"File is empty (0 bytes): {path.name}")

    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if size_bytes > max_bytes:
        raise ValidationError(
            f"File size ({size_bytes / (1024*1024):.2f} MB) exceeds maximum allowed limit of {settings.MAX_UPLOAD_SIZE_MB} MB."
        )

    # Read binary bytes and detect encoding
    file_bytes = path.read_bytes()
    encoding = detect_encoding(file_bytes)

    try:
        decoded_text = file_bytes.decode(encoding)
    except Exception as e:
        raise ValidationError(f"Failed to decode file {path.name} with {encoding} encoding: {e}") from e

    file_format = detect_file_format(decoded_text)
    return decoded_text, file_format
