"""Bob: accepts session, completes handshake, exchanges protected messages."""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from config import APP_MESSAGES_PER_DIRECTION, KEYS_DIR, PORT
from crypto.handshake import BobHandshake, app_receive, app_send
from crypto.identity import load_private_key, load_public_key
from crypto.logutil import log
from transport import accept_peer, receive_message, send_message


def run_bob(port: int, auth_enabled: bool) -> None:
    role = "BOB"
    bob_lt = load_private_key(KEYS_DIR / "bob")
    alice_lt_pub = load_public_key(KEYS_DIR / "trusted" / "alice_ed25519_public.pem")

    log(role, f"listening on TCP port {port}")
    sock, peer = accept_peer(port)
    log(role, f"connected from {peer}", "SUCCESS")

    hs = BobHandshake(bob_lt, alice_lt_pub, auth_enabled=auth_enabled)

    m1 = receive_message(sock)
    m2 = hs.process_m1(m1)
    send_message(sock, m2)
    log(role, "received M1, sent M2", "SUCCESS")

    m3 = receive_message(sock)
    m4 = hs.process_m3(m3)
    send_message(sock, m4)
    log(role, "received M3, sent M4", "SUCCESS")

    session = hs.finish()
    log(role, "handshake authenticated", "SUCCESS")
    log(role, f"transcript_hash={session.secrets.transcript_hash.hex()[:16]}...")
    log(role, "derived directional traffic keys", "SUCCESS")

    replies = [
        "Ack from Bob - message 0",
        "Sensor OK",
        "Final Bob payload",
    ]

    for idx in range(APP_MESSAGES_PER_DIRECTION):
        incoming = receive_message(sock)
        plain = app_receive(session.alice_to_bob, incoming)
        log(role, f"received APP counter={idx} plaintext={plain!r}", "SUCCESS")

        wire = app_send(session.bob_to_alice, replies[idx])
        send_message(sock, wire)
        log(role, f"sent APP reply counter={idx}", "SUCCESS")

    session.discard_ephemeral_material()
    log(role, "session complete, ephemeral material discarded", "SUCCESS")
    sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="CS6530 Assignment 2 - Bob")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument(
        "--no-auth",
        action="store_true",
        help="weakened mode for MITM demo (disables Ed25519 verification/signing)",
    )
    args = parser.parse_args()
    try:
        run_bob(args.port, auth_enabled=not args.no_auth)
    except Exception as exc:
        log("BOB", str(exc), "FAILED")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
