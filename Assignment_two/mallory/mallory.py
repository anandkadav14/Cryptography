"""Mallory MITM proxy for PDF TR-2.

Always substitutes ephemeral public keys.
--weak: Alice/Bob must use --no-auth. Mallory finishes two split sessions and
decrypts / modifies / re-encrypts application records.
Without --weak: same substitution with full Ed25519 on; peers should abort.
"""

import argparse
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from config import ALICE_ID, BOB_ID, APP_MESSAGES_PER_DIRECTION, PORT
from crypto.handshake import app_receive, app_send, session_from_shared
from crypto.hkdf_keys import derive_traffic_keys
from crypto.logutil import fail_text, log
from crypto.transcript import build_transcript, transcript_hash
from crypto.wire import decode_message, encode_message, hx, unhx
from transport import accept_peer, connect_to_peer, receive_message, send_message


def _replace_eph_pk(raw: bytes, field: str, new_pk: bytes) -> bytes:
    msg = decode_message(raw)
    msg[field] = hx(new_pk)
    return encode_message(msg)


def _shared(private: X25519PrivateKey, peer_pk: bytes) -> bytes:
    return private.exchange(X25519PublicKey.from_public_bytes(peer_pk))


def run_mallory(listen_port: int, bob_host: str, bob_port: int, weak: bool) -> None:
    role = "MALLORY"
    log(role, f"waiting for Alice on port {listen_port}")
    alice_sock, alice_addr = accept_peer(listen_port)
    log(role, f"Alice connected from {alice_addr}", "SUCCESS")

    log(role, f"connecting to real Bob at {bob_host}:{bob_port}")
    bob_sock = connect_to_peer(bob_host, bob_port)
    log(role, "connected to Bob", "SUCCESS")

    mallory_to_bob = X25519PrivateKey.generate()
    mallory_to_alice = X25519PrivateKey.generate()
    fake_alice_eph_pk = mallory_to_bob.public_key().public_bytes_raw()
    fake_bob_eph_pk = mallory_to_alice.public_key().public_bytes_raw()

    m1 = receive_message(alice_sock)
    m1_obj = decode_message(m1)
    alice_sid = unhx(m1_obj["alice_sid"])
    real_alice_eph_pk = unhx(m1_obj["alice_eph_pk"])
    log(role, "substituting Alice ephemeral public key in M1")
    send_message(bob_sock, _replace_eph_pk(m1, "alice_eph_pk", fake_alice_eph_pk))

    m2 = receive_message(bob_sock)
    m2_obj = decode_message(m2)
    bob_sid = unhx(m2_obj["bob_sid"])
    real_bob_eph_pk = unhx(m2_obj["bob_eph_pk"])
    log(role, "substituting Bob ephemeral public key in M2")
    send_message(alice_sock, _replace_eph_pk(m2, "bob_eph_pk", fake_bob_eph_pk))

    try:
        m3 = receive_message(alice_sock)
        send_message(bob_sock, m3)
        m4 = receive_message(bob_sock)
        send_message(alice_sock, m4)
    except Exception as exc:
        log(role, f"peer aborted during handshake: {fail_text(exc)}", "SUCCESS")
        alice_sock.close()
        bob_sock.close()
        return

    if not weak:
        log(
            role,
            "full auth: swapped ephemeral keys; Alice/Bob signatures should fail and abort",
            "INFO",
        )
        alice_sock.close()
        bob_sock.close()
        return

    shared_alice = _shared(mallory_to_alice, real_alice_eph_pk)
    shared_bob = _shared(mallory_to_bob, real_bob_eph_pk)
    th_alice = transcript_hash(
        build_transcript(ALICE_ID, BOB_ID, alice_sid, bob_sid, real_alice_eph_pk, fake_bob_eph_pk)
    )
    th_bob = transcript_hash(
        build_transcript(ALICE_ID, BOB_ID, alice_sid, bob_sid, fake_alice_eph_pk, real_bob_eph_pk)
    )
    k_a2b_alice, k_b2a_alice = derive_traffic_keys(shared_alice, th_alice)
    k_a2b_bob, k_b2a_bob = derive_traffic_keys(shared_bob, th_bob)
    log(role, f"Alice-Mallory transcript_hash={th_alice.hex()[:16]}...")
    log(role, f"Mallory-Bob transcript_hash={th_bob.hex()[:16]}...")
    log(role, "split secrets established (Alice-Mallory and Mallory-Bob)", "SUCCESS")

    alice_view = session_from_shared(
        alice_sid, bob_sid, real_alice_eph_pk, fake_bob_eph_pk, shared_alice
    )
    bob_view = session_from_shared(
        alice_sid, bob_sid, fake_alice_eph_pk, real_bob_eph_pk, shared_bob
    )
    if k_a2b_alice == k_a2b_bob:
        raise RuntimeError("MITM split failed: both sides derived the same traffic key")

    for idx in range(APP_MESSAGES_PER_DIRECTION):
        from_alice = receive_message(alice_sock)
        plain = app_receive(alice_view.alice_to_bob, from_alice)
        log(role, f"decrypted Alice APP counter={idx}: {plain!r}", "SUCCESS")
        modified = f"MALLORY-EDITED: {plain}"
        send_message(bob_sock, app_send(bob_view.alice_to_bob, modified))
        log(role, f"re-encrypted modified APP to Bob: {modified!r}", "SUCCESS")

        from_bob = receive_message(bob_sock)
        reply = app_receive(bob_view.bob_to_alice, from_bob)
        log(role, f"decrypted Bob APP counter={idx}: {reply!r}", "SUCCESS")
        send_message(alice_sock, app_send(alice_view.bob_to_alice, reply))

    log(role, "weakened MITM complete: decrypted, modified, re-encrypted", "SUCCESS")
    alice_sock.close()
    bob_sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="CS6530 Assignment 2 - Mallory MITM proxy")
    parser.add_argument("--listen-port", type=int, default=PORT)
    parser.add_argument("--bob-host", default="127.0.0.1")
    parser.add_argument("--bob-port", type=int, default=PORT + 1)
    parser.add_argument(
        "--weak",
        action="store_true",
        help="PDF TR-2 weakened mode: decrypt/modify/re-encrypt APP (Alice/Bob --no-auth)",
    )
    args = parser.parse_args()
    try:
        run_mallory(args.listen_port, args.bob_host, args.bob_port, weak=args.weak)
    except Exception as exc:
        log("MALLORY", fail_text(exc), "FAILED")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
