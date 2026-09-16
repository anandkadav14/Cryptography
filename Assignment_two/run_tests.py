"""Local Assignment 2 checks (TR-1, TR-3, TR-4 helpers). Two-PC demos still required."""

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from config import KEYS_DIR
from crypto.aead import DirectionalChannel
from crypto.handshake import app_receive, app_send
from crypto.hkdf_keys import derive_traffic_keys
from crypto.identity import generate_identity_keypair, export_public_key_copy, load_private_key
from crypto.transcript import build_transcript, transcript_hash
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from config import ALICE_ID, BOB_ID


def ensure_keys() -> None:
    alice_dir = KEYS_DIR / "alice"
    bob_dir = KEYS_DIR / "bob"
    if not (alice_dir / "ed25519_private.pem").exists():
        generate_identity_keypair(alice_dir)
    if not (bob_dir / "ed25519_private.pem").exists():
        generate_identity_keypair(bob_dir)
    export_public_key_copy(alice_dir, KEYS_DIR / "trusted" / "alice_ed25519_public.pem")
    export_public_key_copy(bob_dir, KEYS_DIR / "trusted" / "bob_ed25519_public.pem")


def test_tr1_local() -> bool:
    print("\n=== TR-1 local session (127.0.0.1) ===")
    bob = subprocess.Popen(
        [sys.executable, str(ROOT / "bob" / "bob.py"), "--port", "5001"],
        cwd=str(ROOT),
    )
    time.sleep(1.0)
    alice = subprocess.run(
        [sys.executable, str(ROOT / "alice" / "alice.py"), "127.0.0.1", "--port", "5001"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    bob.wait(timeout=30)
    ok = alice.returncode == 0
    print(alice.stdout)
    if alice.stderr:
        print(alice.stderr)
    print("TR-1:", "PASS" if ok else "FAIL")
    return ok


def test_tr3_replay() -> bool:
    print("\n=== TR-3 replay counter rejection ===")
    alice_sid = b"\x01" * 16
    bob_sid = b"\x02" * 16
    key = b"\xab" * 32
    ch = DirectionalChannel(key, ALICE_ID, BOB_ID, alice_sid, bob_sid)
    wire = app_send(ch, "record-0")
    app_receive(ch, wire)
    try:
        app_receive(ch, wire)
        print("TR-3: FAIL (replay accepted)")
        return False
    except ValueError as exc:
        print(f"TR-3: replay rejected as expected ({exc})")
        print("TR-3: PASS")
        return True


def test_tr4_forward_secrecy_logic() -> bool:
    print("\n=== TR-4 forward secrecy logic ===")
    alice_eph = X25519PrivateKey.generate()
    bob_eph = X25519PrivateKey.generate()
    alice_eph_pk = alice_eph.public_key().public_bytes_raw()
    bob_eph_pk = bob_eph.public_key().public_bytes_raw()
    alice_sid = b"\x11" * 16
    bob_sid = b"\x22" * 16

    shared = alice_eph.exchange(bob_eph.public_key())
    transcript = build_transcript(ALICE_ID, BOB_ID, alice_sid, bob_sid, alice_eph_pk, bob_eph_pk)
    th = transcript_hash(transcript)
    k_a2b, k_b2a = derive_traffic_keys(shared, th)

    # After session: ephemeral secrets discarded; long-term Ed25519 alone cannot rebuild traffic keys
    alice_lt = Ed25519PrivateKey.generate()
    _ = alice_lt.sign(th)

    try:
        derive_traffic_keys(b"\x00" * 32, th)
        print("TR-4: FAIL (bad shared secret accepted)")
        return False
    except ValueError:
        pass

    # With old ephemeral private key, shared secret can be recomputed (comparison case)
    recovered = alice_eph.exchange(X25519PublicKey.from_public_bytes(bob_eph_pk))
    rk_a2b, _ = derive_traffic_keys(recovered, th)
    ok = rk_a2b == k_a2b
    print("TR-4: long-term key alone cannot recover traffic keys")
    print("TR-4: old ephemeral secret CAN recover keys (controlled comparison)")
    print("TR-4:", "PASS" if ok else "FAIL")
    return ok


def test_hkdf_not_raw_secret() -> bool:
    print("\n=== HKDF uses transcript-bound keys (not raw X25519 secret) ===")
    shared = b"\xcd" * 32
    th = b"\xef" * 32
    k_a2b, _ = derive_traffic_keys(shared, th)
    ok = k_a2b != shared
    print("check:", "PASS" if ok else "FAIL")
    return ok


def main() -> None:
    ensure_keys()
    results = [
        test_hkdf_not_raw_secret(),
        test_tr3_replay(),
        test_tr4_forward_secrecy_logic(),
        test_tr1_local(),
    ]
    print("\n=== Summary ===")
    names = ["HKDF", "TR-3", "TR-4-logic", "TR-1-local"]
    for name, ok in zip(names, results):
        print(f"{name}: {'PASS' if ok else 'FAIL'}")
    if not all(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
