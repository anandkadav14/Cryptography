"""Alice: initiates authenticated ephemeral session and sends protected messages."""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from config import APP_MESSAGES_PER_DIRECTION, KEYS_DIR, PORT
from crypto.handshake import AliceHandshake, app_receive, app_send
from crypto.identity import load_private_key, load_public_key
from crypto.logutil import log
from transport import connect_to_peer, receive_message, send_message


def run_alice(peer_ip: str, port: int, auth_enabled: bool) -> None:
    role = "ALICE"
    alice_lt = load_private_key(KEYS_DIR / "alice")
    bob_lt_pub = load_public_key(KEYS_DIR / "trusted" / "bob_ed25519_public.pem")

    log(role, f"connecting to {peer_ip}:{port}")
    sock = connect_to_peer(peer_ip, port)
    log(role, "connected", "SUCCESS")

    hs = AliceHandshake(alice_lt, bob_lt_pub, auth_enabled=auth_enabled)

    send_message(sock, hs.m1())
    log(role, "sent M1", "SUCCESS")

    m2 = receive_message(sock)
    m3 = hs.process_m2(m2)
    log(role, "received M2, verified Alice_SID", "SUCCESS")

    send_message(sock, m3)
    log(role, "sent M3", "SUCCESS")

    m4 = receive_message(sock)
    session = hs.process_m4(m4)
    log(role, "received M4, handshake authenticated", "SUCCESS")
    log(role, f"transcript_hash={session.secrets.transcript_hash.hex()[:16]}...")
    log(role, "derived directional traffic keys (not raw X25519 secret)", "SUCCESS")

    samples = [
        "Hello Bob - message 0",
        "Temperature reading: 27.5C",
        "Final Alice payload",
    ]
    for idx, text in enumerate(samples[:APP_MESSAGES_PER_DIRECTION]):
        wire = app_send(session.alice_to_bob, text)
        send_message(sock, wire)
        log(role, f"sent APP counter={idx} plaintext={text!r}", "SUCCESS")

        reply_raw = receive_message(sock)
        reply = app_receive(session.bob_to_alice, reply_raw)
        log(role, f"received APP from Bob: {reply!r}", "SUCCESS")

    session.discard_ephemeral_material()
    log(role, "session complete, ephemeral material discarded", "SUCCESS")
    sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="CS6530 Assignment 2 - Alice")
    parser.add_argument("peer_ip", help="Bob IP address")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument(
        "--no-auth",
        action="store_true",
        help="weakened mode for MITM demo (disables Ed25519 verification/signing)",
    )
    args = parser.parse_args()
    try:
        run_alice(args.peer_ip, args.port, auth_enabled=not args.no_auth)
    except Exception as exc:
        log("ALICE", str(exc), "FAILED")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
