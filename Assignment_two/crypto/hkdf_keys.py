"""HKDF-SHA-256 session key derivation."""

import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from config import HKDF_INFO_A2B, HKDF_INFO_B2A


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def derive_traffic_keys(shared_secret: bytes, transcript_hash_value: bytes) -> tuple[bytes, bytes]:
    if shared_secret == bytes([0] * 32):
        raise ValueError("invalid all-zero X25519 shared secret")

    prk = _hkdf_extract(transcript_hash_value, shared_secret)

    k_a2b = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=HKDF_INFO_A2B,
    ).derive(prk)

    k_b2a = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=HKDF_INFO_B2A,
    ).derive(prk)

    if k_a2b == shared_secret or k_b2a == shared_secret:
        raise ValueError("traffic key must not equal raw shared secret")

    return k_a2b, k_b2a
