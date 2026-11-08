"""Verify model bytes before allowing pickle-based deserialization."""
import hashlib
import hmac
import re
from pathlib import Path


def verified_artifact_bytes(path: Path, expected_sha256: str) -> bytes:
    """Fail closed, including for legacy metadata without an artifact hash."""
    prefix = f"Model artifact integrity check failed: {path.name}"
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError(f"{prefix}: missing or invalid SHA-256. Retrain before scanning.")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"{prefix}: cannot read artifact. Retrain before scanning.") from exc
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected_sha256):
        raise ValueError(f"{prefix}: SHA-256 mismatch. Retrain before scanning.")
    return data
