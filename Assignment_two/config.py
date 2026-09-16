"""Assignment 2 protocol constants."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent
KEYS_DIR = ROOT / "keys"

PORT = 5000

PROTOCOL_ID = b"CS6530-A2-v1"
TRANSCRIPT_LEN = 124

# 8-character roll numbers (ASCII, padded/truncated to exactly 8 bytes)
ALICE_ID = b"IC43333 "
BOB_ID = b"IC43332 "

HKDF_INFO_A2B = b"CS6530-A2 Alice->Bob"
HKDF_INFO_B2A = b"CS6530-A2 Bob->Alice"

APP_MESSAGES_PER_DIRECTION = 3
