"""Canonical handshake transcript and hash."""

import hashlib
import struct

from config import PROTOCOL_ID, TRANSCRIPT_LEN


def normalize_id(raw: bytes) -> bytes:
    if len(raw) != 8:
        raise ValueError(f"ID must be exactly 8 bytes, got {len(raw)}")
    return raw


def build_transcript(
    alice_id: bytes,
    bob_id: bytes,
    alice_sid: bytes,
    bob_sid: bytes,
    alice_eph_pk: bytes,
    bob_eph_pk: bytes,
) -> bytes:
    parts = [
        PROTOCOL_ID,
        normalize_id(alice_id),
        normalize_id(bob_id),
        alice_sid,
        bob_sid,
        alice_eph_pk,
        bob_eph_pk,
    ]
    for name, part, expected in [
        ("protocol_id", PROTOCOL_ID, 12),
        ("alice_sid", alice_sid, 16),
        ("bob_sid", bob_sid, 16),
        ("alice_eph_pk", alice_eph_pk, 32),
        ("bob_eph_pk", bob_eph_pk, 32),
    ]:
        if len(part) != expected and name != "protocol_id":
            raise ValueError(f"{name} must be {expected} bytes, got {len(part)}")
    transcript = b"".join(parts)
    if len(transcript) != TRANSCRIPT_LEN:
        raise ValueError(f"transcript length {len(transcript)} != {TRANSCRIPT_LEN}")
    return transcript


def transcript_hash(transcript: bytes) -> bytes:
    if len(transcript) != TRANSCRIPT_LEN:
        raise ValueError("invalid transcript length")
    return hashlib.sha256(transcript).digest()


def counter_to_bytes(counter: int) -> bytes:
    if counter < 0 or counter >= 2**64:
        raise ValueError("counter out of uint64 range")
    return struct.pack(">Q", counter)
