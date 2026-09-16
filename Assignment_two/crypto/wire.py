"""JSON wire encoding for protocol messages."""

import json
from typing import Any


def encode_message(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def decode_message(data: bytes) -> dict[str, Any]:
    obj = json.loads(data.decode("utf-8"))
    if not isinstance(obj, dict) or "type" not in obj:
        raise ValueError("invalid protocol message")
    return obj


def hx(data: bytes) -> str:
    return data.hex()


def unhx(text: str) -> bytes:
    return bytes.fromhex(text)
