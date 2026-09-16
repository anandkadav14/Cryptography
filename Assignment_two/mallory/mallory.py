"""Mallory MITM proxy for TR-2 demonstration."""

import argparse
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from config import PORT
from crypto.logutil import log
from crypto.wire import decode_message, encode_message, hx, unhx
from transport import accept_peer, connect_to_peer, receive_message, send_message


def _replace_eph_pk(raw: bytes, field: str, new_pk: bytes) -> bytes:
    msg = decode_message(raw)
    msg[field] = hx(new_pk)
    return encode_message(msg)


def run_mallory(listen_port: int, bob_host: str, bob_port: int, auth_attack: bool) -> None:
    role = "MALLORY"
    log(role, f"waiting for Alice on port {listen_port}")
    alice_sock, alice_addr = accept_peer(listen_port)
    log(role, f"Alice connected from {alice_addr}", "SUCCESS")

    log(role, f"connecting to real Bob at {bob_host}:{bob_port}")
    bob_sock = connect_to_peer(bob_host, bob_port)
    log(role, "connected to Bob", "SUCCESS")

    mallory_a = X25519PrivateKey.generate()
    mallory_b = X25519PrivateKey.generate()
    mallory_a_pk = mallory_a.public_key().public_bytes_raw()
    mallory_b_pk = mallory_b.public_key().public_bytes_raw()

    # M1 Alice -> Bob (substitute Alice ephemeral PK if attacking)
    m1 = receive_message(alice_sock)
    if not auth_attack:
        log(role, "weakened mode: substituting Alice ephemeral public key", "INFO")
        m1 = _replace_eph_pk(m1, "alice_eph_pk", mallory_a_pk)
    send_message(bob_sock, m1)

    # M2 Bob -> Alice
    m2 = receive_message(bob_sock)
    if not auth_attack:
        log(role, "weakened mode: substituting Bob ephemeral public key", "INFO")
        m2 = _replace_eph_pk(m2, "bob_eph_pk", mallory_b_pk)
    send_message(alice_sock, m2)

    # M3 Alice -> Bob
    m3 = receive_message(alice_sock)
    send_message(bob_sock, m3)

    # M4 Bob -> Alice
    m4 = receive_message(bob_sock)
    send_message(alice_sock, m4)

    if auth_attack:
        log(role, "full auth mode: ephemeral substitution should cause signature failure on peers", "INFO")
    else:
        log(role, "weakened MITM path complete (no identity authentication)", "SUCCESS")

    alice_sock.close()
    bob_sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="CS6530 Assignment 2 - Mallory MITM proxy")
    parser.add_argument("--listen-port", type=int, default=PORT)
    parser.add_argument("--bob-host", default="127.0.0.1")
    parser.add_argument("--bob-port", type=int, default=PORT + 1)
    parser.add_argument(
        "--auth-attack",
        action="store_true",
        help="forward substituted keys with full auth enabled (expect peer abort)",
    )
    args = parser.parse_args()
    try:
        run_mallory(args.listen_port, args.bob_host, args.bob_port, args.auth_attack)
    except Exception as exc:
        log("MALLORY", str(exc), "FAILED")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
