"""Associated Data (AAD) helpers for binding record metadata into AEAD."""


def build_record_aad(sequence: int, user_aad: bytes = b"") -> bytes:
    """
    Build canonical AAD that binds the sequence number into AEAD auth.

    Format: b"seq=<sequence>|" + optional user metadata bytes
    """
    if user_aad is None:
        user_aad = b""
    return f"seq={sequence}|".encode("utf-8") + user_aad


def aad_matches_sequence(aad: bytes, sequence: int) -> bool:
    """Return True if AAD starts with the expected sequence prefix."""
    prefix = f"seq={sequence}|".encode("utf-8")
    return aad.startswith(prefix)
