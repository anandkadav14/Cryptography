"""PDF TR-3: capture a valid APP record and replay it unchanged."""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from config import PORT
from crypto.logutil import fail_text, log
from crypto.wire import decode_message
from transport import accept_peer, connect_to_peer, receive_message, send_message


def run_replay(listen_port: int, bob_host: str, bob_port: int) -> None:
    role = "REPLAY"
    log(role, f"waiting for Alice on port {listen_port}")
    alice_sock, alice_addr = accept_peer(listen_port)
    log(role, f"Alice connected from {alice_addr}", "SUCCESS")
    bob_sock = connect_to_peer(bob_host, bob_port)
    log(role, f"connected to Bob at {bob_host}:{bob_port}", "SUCCESS")

    for name in ("M1", "M3"):
        raw = receive_message(alice_sock)
        send_message(bob_sock, raw)
        log(role, f"forwarded {name}")
        raw = receive_message(bob_sock)
        send_message(alice_sock, raw)
        log(role, f"forwarded {'M2' if name == 'M1' else 'M4'}")

    original = receive_message(alice_sock)
    app = decode_message(original)
    log(
        role,
        f"captured APP counter={app.get('counter')} nonce={str(app.get('nonce'))[:16]}...",
        "SUCCESS",
    )
    send_message(bob_sock, original)
    log(role, "forwarded original APP to Bob (expect ACCEPT)", "SUCCESS")

    reply = receive_message(bob_sock)
    send_message(alice_sock, reply)
    log(role, "forwarded Bob reply for original record")

    send_message(bob_sock, original)
    log(role, "replayed the SAME APP unchanged (expect REJECT)", "SUCCESS")
    try:
        extra = receive_message(bob_sock)
        log(role, f"unexpected extra data from Bob: {extra[:40]!r}", "FAILED")
    except Exception as exc:
        log(role, f"Bob closed/rejected replay: {fail_text(exc)}", "SUCCESS")

    alice_sock.close()
    bob_sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="CS6530 Assignment 2 - TR-3 live replay")
    parser.add_argument("--listen-port", type=int, default=PORT)
    parser.add_argument("--bob-host", default="127.0.0.1")
    parser.add_argument("--bob-port", type=int, default=PORT + 1)
    args = parser.parse_args()
    try:
        run_replay(args.listen_port, args.bob_host, args.bob_port)
    except Exception as exc:
        log("REPLAY", fail_text(exc), "FAILED")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
