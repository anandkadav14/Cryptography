"""PDF TR-4: recorded session S1, then long-term vs ephemeral compromise."""

import argparse
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from config import ALICE_ID, BOB_ID, KEYS_DIR
from crypto.aead import DirectionalChannel
from crypto.hkdf_keys import derive_traffic_keys
from crypto.identity import load_private_key
from crypto.logutil import fail_text, log
from crypto.wire import unhx


def main() -> None:
    parser = argparse.ArgumentParser(description="CS6530 Assignment 2 - TR-4 forward secrecy")
    parser.add_argument("record", help="JSON saved by bob.py --save-s1")
    args = parser.parse_args()
    role = "TR-4"
    data = json.loads(Path(args.record).read_text(encoding="utf-8"))

    th = unhx(data["transcript_hash"])
    bob_eph_sk = unhx(data["bob_eph_sk"])
    alice_eph_pk = unhx(data["alice_eph_pk"])
    saved_k_a2b = unhx(data["k_a2b"])
    app0 = data["app0"]
    alice_id = unhx(data["alice_id"]) if "alice_id" in data else ALICE_ID
    bob_id = unhx(data["bob_id"]) if "bob_id" in data else BOB_ID

    log(role, f"loaded recorded session S1 from {args.record}", "SUCCESS")
    log(role, f"S1 transcript_hash={th.hex()[:16]}...")
    log(role, f"S1 captured APP counter={app0['counter']} ct={str(app0['ciphertext'])[:16]}...")

    alice_lt = load_private_key(KEYS_DIR / "alice")
    signature = alice_lt.sign(th)
    log(role, f"compromised Alice Ed25519 can SIGN transcript ({signature[:8].hex()}...)", "SUCCESS")

    lt_raw = alice_lt.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    k_from_lt, _ = derive_traffic_keys(lt_raw, th)
    if k_from_lt == saved_k_a2b:
        log(role, "long-term key material unexpectedly matched S1 traffic key", "FAILED")
        raise SystemExit(1)
    log(role, "past S1 traffic keys NOT reconstructed from long-term Ed25519", "SUCCESS")

    bob_eph = X25519PrivateKey.from_private_bytes(bob_eph_sk)
    shared = bob_eph.exchange(X25519PublicKey.from_public_bytes(alice_eph_pk))
    k_a2b, _k_b2a = derive_traffic_keys(shared, th)
    if k_a2b != saved_k_a2b:
        log(role, "old ephemeral reconstruction did not match saved K_Alice_to_Bob", "FAILED")
        raise SystemExit(1)
    log(role, "old ephemeral X25519 private key DID reconstruct S1 traffic keys", "SUCCESS")

    ch = DirectionalChannel(k_a2b, alice_id, bob_id, unhx(data["alice_sid"]), unhx(data["bob_sid"]))
    plaintext = ch.decrypt(unhx(app0["ciphertext"]), int(app0["counter"]))
    log(role, f"with old X25519, recorded APP decrypts to {plaintext!r}", "SUCCESS")
    log(role, "forward secrecy: discard ephemerals; later LT compromise does not open S1", "SUCCESS")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        log("TR-4", fail_text(exc), "FAILED")
        raise SystemExit(1) from exc
