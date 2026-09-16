"""Bob: accepts session, completes handshake, exchanges protected messages."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from config import ALICE_ID, APP_MESSAGES_PER_DIRECTION, BOB_ID, KEYS_DIR, PORT
from crypto.handshake import BobHandshake, app_receive, app_send
from crypto.identity import load_private_key, load_public_key
from crypto.logutil import fail_text, log
from crypto.wire import decode_message, hx
from transport import accept_peer, receive_message, send_message


def _log_session(role: str, session) -> None:
    s = session.secrets
    log(role, f"alice_sid={s.alice_sid.hex()}")
    log(role, f"bob_sid={s.bob_sid.hex()}")
    log(role, f"transcript_len={len(s.transcript)} transcript_hash={s.transcript_hash.hex()[:16]}...")
    same = s.shared_secret == s.k_a2b or s.shared_secret == s.k_b2a
    log(role, f"raw X25519 used directly as AES key? {same}", "FAILED" if same else "SUCCESS")
    log(role, "derived directional traffic keys via HKDF-SHA-256", "SUCCESS")


def run_bob(port: int, auth_enabled: bool, save_s1: Path | None) -> None:
    role = "BOB"
    if not auth_enabled:
        log(role, "WEAK MODE: Ed25519 authentication disabled")
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
    _log_session(role, session)

    replies = [
        "Ack from Bob - message 0",
        "Sensor OK",
        "Final Bob payload",
    ]
    first_app = None

    for idx in range(APP_MESSAGES_PER_DIRECTION):
        incoming = receive_message(sock)
        fields = decode_message(incoming)
        if first_app is None:
            first_app = fields
        try:
            plain = app_receive(session.alice_to_bob, incoming)
        except ValueError as exc:
            log(role, f"APP rejected: {exc}", "REJECTED")
            raise
        log(
            role,
            f"received APP counter={fields['counter']} nonce={fields['nonce'][:16]}... plaintext={plain!r}",
            "SUCCESS",
        )

        wire = app_send(session.bob_to_alice, replies[idx])
        send_message(sock, wire)
        log(role, f"sent APP reply counter={idx}", "SUCCESS")

    if save_s1 is not None:
        if first_app is None:
            raise RuntimeError("no APP record to save for TR-4")
        archive = session.archive_for_forward_secrecy()
        archive.update(
            {
                "alice_id": hx(ALICE_ID),
                "bob_id": hx(BOB_ID),
                "app0": first_app,
            }
        )
        save_s1.parent.mkdir(parents=True, exist_ok=True)
        save_s1.write_text(json.dumps(archive, indent=2), encoding="utf-8")
        log(role, f"recorded S1 to {save_s1}", "SUCCESS")

    session.discard_ephemeral_material()
    log(role, "session complete, ephemeral material discarded", "SUCCESS")
    sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="CS6530 Assignment 2 - Bob")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument(
        "--no-auth",
        action="store_true",
        help="PDF TR-2 weakened mode (disable Ed25519)",
    )
    parser.add_argument(
        "--save-s1",
        type=Path,
        default=None,
        help="PDF TR-4: write recorded session JSON before discarding ephemerals",
    )
    args = parser.parse_args()
    try:
        run_bob(args.port, auth_enabled=not args.no_auth, save_s1=args.save_s1)
    except Exception as exc:
        log("BOB", fail_text(exc), "FAILED")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
