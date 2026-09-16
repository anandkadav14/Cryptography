"""Authenticated ephemeral handshake and session state."""

import os
import secrets
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from config import ALICE_ID, BOB_ID
from crypto.aead import DirectionalChannel
from crypto.hkdf_keys import derive_traffic_keys
from crypto.transcript import build_transcript, transcript_hash
from crypto.wire import decode_message, encode_message, hx, unhx


@dataclass
class SessionSecrets:
    alice_sid: bytes
    bob_sid: bytes
    alice_eph_pk: bytes
    bob_eph_pk: bytes
    transcript: bytes
    transcript_hash: bytes
    shared_secret: bytes
    k_a2b: bytes
    k_b2a: bytes
    alice_signature: bytes = b""
    bob_signature: bytes = b""


@dataclass
class SessionRuntime:
    secrets: SessionSecrets
    alice_to_bob: DirectionalChannel
    bob_to_alice: DirectionalChannel
    auth_enabled: bool = True
    _ephemeral_private: dict[str, bytes] = field(default_factory=dict)

    def discard_ephemeral_material(self) -> None:
        self.secrets.shared_secret = b""
        self.secrets.k_a2b = b""
        self.secrets.k_b2a = b""
        self._ephemeral_private.clear()

    def archive_for_forward_secrecy(self) -> dict:
        return {
            "alice_sid": hx(self.secrets.alice_sid),
            "bob_sid": hx(self.secrets.bob_sid),
            "transcript_hash": hx(self.secrets.transcript_hash),
            "shared_secret": hx(self.secrets.shared_secret),
            "k_a2b": hx(self.secrets.k_a2b),
            "k_b2a": hx(self.secrets.k_b2a),
            "alice_eph_pk": hx(self.secrets.alice_eph_pk),
            "bob_eph_pk": hx(self.secrets.bob_eph_pk),
            "alice_eph_sk": hx(self._ephemeral_private.get("alice", b"")),
            "bob_eph_sk": hx(self._ephemeral_private.get("bob", b"")),
        }


def _x25519_shared(our_private: X25519PrivateKey, peer_public_raw: bytes) -> bytes:
    peer = X25519PublicKey.from_public_bytes(peer_public_raw)
    return our_private.exchange(peer)


def _build_session(
    alice_sid: bytes,
    bob_sid: bytes,
    alice_eph_pk: bytes,
    bob_eph_pk: bytes,
    shared_secret: bytes,
) -> SessionRuntime:
    transcript = build_transcript(ALICE_ID, BOB_ID, alice_sid, bob_sid, alice_eph_pk, bob_eph_pk)
    th = transcript_hash(transcript)
    k_a2b, k_b2a = derive_traffic_keys(shared_secret, th)
    secrets = SessionSecrets(
        alice_sid=alice_sid,
        bob_sid=bob_sid,
        alice_eph_pk=alice_eph_pk,
        bob_eph_pk=bob_eph_pk,
        transcript=transcript,
        transcript_hash=th,
        shared_secret=shared_secret,
        k_a2b=k_a2b,
        k_b2a=k_b2a,
    )
    alice_to_bob = DirectionalChannel(k_a2b, ALICE_ID, BOB_ID, alice_sid, bob_sid)
    bob_to_alice = DirectionalChannel(k_b2a, BOB_ID, ALICE_ID, alice_sid, bob_sid)
    return SessionRuntime(secrets=secrets, alice_to_bob=alice_to_bob, bob_to_alice=bob_to_alice)


class AliceHandshake:
    def __init__(self, alice_lt: Ed25519PrivateKey, bob_lt_pub: Ed25519PublicKey, auth_enabled: bool = True):
        self.alice_lt = alice_lt
        self.bob_lt_pub = bob_lt_pub
        self.auth_enabled = auth_enabled
        self.alice_sid = secrets.token_bytes(16)
        self.alice_eph = X25519PrivateKey.generate()
        self.alice_eph_pk = self.alice_eph.public_key().public_bytes_raw()

    def m1(self) -> bytes:
        return encode_message(
            {
                "type": "M1",
                "alice_sid": hx(self.alice_sid),
                "alice_eph_pk": hx(self.alice_eph_pk),
            }
        )

    def process_m2(self, raw: bytes) -> bytes:
        msg = decode_message(raw)
        if msg["type"] != "M2":
            raise ValueError("expected M2")
        if unhx(msg["alice_sid"]) != self.alice_sid:
            raise ValueError("Alice_SID mismatch in M2")
        bob_sid = unhx(msg["bob_sid"])
        bob_eph_pk = unhx(msg["bob_eph_pk"])
        transcript = build_transcript(ALICE_ID, BOB_ID, self.alice_sid, bob_sid, self.alice_eph_pk, bob_eph_pk)
        th = transcript_hash(transcript)
        alice_sig = self.alice_lt.sign(th) if self.auth_enabled else b"\x00" * 64
        self._pending = (bob_sid, bob_eph_pk, transcript, th, alice_sig)
        return encode_message({"type": "M3", "alice_signature": hx(alice_sig)})

    def process_m4(self, raw: bytes) -> SessionRuntime:
        msg = decode_message(raw)
        if msg["type"] != "M4":
            raise ValueError("expected M4")
        bob_sid, bob_eph_pk, transcript, th, alice_sig = self._pending
        bob_sig = unhx(msg["bob_signature"])
        if self.auth_enabled:
            self.bob_lt_pub.verify(bob_sig, th)
        shared = _x25519_shared(self.alice_eph, bob_eph_pk)
        session = _build_session(self.alice_sid, bob_sid, self.alice_eph_pk, bob_eph_pk, shared)
        session.secrets.alice_signature = alice_sig
        session.secrets.bob_signature = bob_sig
        session.auth_enabled = self.auth_enabled
        session._ephemeral_private["alice"] = self.alice_eph.private_bytes_raw()
        return session


class BobHandshake:
    def __init__(self, bob_lt: Ed25519PrivateKey, alice_lt_pub: Ed25519PublicKey, auth_enabled: bool = True):
        self.bob_lt = bob_lt
        self.alice_lt_pub = alice_lt_pub
        self.auth_enabled = auth_enabled
        self.bob_sid = secrets.token_bytes(16)
        self.bob_eph = X25519PrivateKey.generate()
        self.bob_eph_pk = self.bob_eph.public_key().public_bytes_raw()

    def process_m1(self, raw: bytes) -> bytes:
        msg = decode_message(raw)
        if msg["type"] != "M1":
            raise ValueError("expected M1")
        self.alice_sid = unhx(msg["alice_sid"])
        self.alice_eph_pk = unhx(msg["alice_eph_pk"])
        return encode_message(
            {
                "type": "M2",
                "alice_sid": hx(self.alice_sid),
                "bob_sid": hx(self.bob_sid),
                "bob_eph_pk": hx(self.bob_eph_pk),
            }
        )

    def process_m3(self, raw: bytes) -> bytes:
        msg = decode_message(raw)
        if msg["type"] != "M3":
            raise ValueError("expected M3")
        alice_sig = unhx(msg["alice_signature"])
        transcript = build_transcript(
            ALICE_ID, BOB_ID, self.alice_sid, self.bob_sid, self.alice_eph_pk, self.bob_eph_pk
        )
        th = transcript_hash(transcript)
        if self.auth_enabled:
            self.alice_lt_pub.verify(alice_sig, th)
        bob_sig = self.bob_lt.sign(th) if self.auth_enabled else b"\x00" * 64
        self._pending = (transcript, th, alice_sig, bob_sig)
        return encode_message({"type": "M4", "bob_signature": hx(bob_sig)})

    def finish(self) -> SessionRuntime:
        transcript, th, alice_sig, bob_sig = self._pending
        shared = _x25519_shared(self.bob_eph, self.alice_eph_pk)
        session = _build_session(self.alice_sid, self.bob_sid, self.alice_eph_pk, self.bob_eph_pk, shared)
        session.secrets.alice_signature = alice_sig
        session.secrets.bob_signature = bob_sig
        session.auth_enabled = self.auth_enabled
        session._ephemeral_private["bob"] = self.bob_eph.private_bytes_raw()
        return session


def app_send(channel: DirectionalChannel, plaintext: str) -> bytes:
    ct, nonce, aad, counter = channel.encrypt(plaintext.encode("utf-8"))
    return encode_message(
        {
            "type": "APP",
            "counter": counter,
            "ciphertext": hx(ct),
            "nonce": hx(nonce),
            "aad": hx(aad),
        }
    )


def app_receive(channel: DirectionalChannel, raw: bytes) -> str:
    msg = decode_message(raw)
    if msg["type"] != "APP":
        raise ValueError("expected APP")
    counter = int(msg["counter"])
    ct = unhx(msg["ciphertext"])
    plaintext = channel.decrypt(ct, counter)
    return plaintext.decode("utf-8")
