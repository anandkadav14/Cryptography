"""AES-256-GCM protected application records."""

import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto.transcript import counter_to_bytes, normalize_id


def build_aad(
    sender_id: bytes,
    receiver_id: bytes,
    alice_sid: bytes,
    bob_sid: bytes,
    counter: int,
) -> bytes:
    return (
        normalize_id(sender_id)
        + normalize_id(receiver_id)
        + alice_sid
        + bob_sid
        + counter_to_bytes(counter)
    )


def build_nonce(counter: int) -> bytes:
    return b"\x00\x00\x00\x00" + counter_to_bytes(counter)


class DirectionalChannel:
    """Encrypt/decrypt for one traffic direction with monotonic counters."""

    def __init__(
        self,
        key: bytes,
        sender_id: bytes,
        receiver_id: bytes,
        alice_sid: bytes,
        bob_sid: bytes,
        send_counter: int = 0,
        recv_counter: int = 0,
    ):
        self._aes = AESGCM(key)
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.alice_sid = alice_sid
        self.bob_sid = bob_sid
        self.send_counter = send_counter
        self.recv_counter = recv_counter

    def encrypt(self, plaintext: bytes) -> tuple[bytes, bytes, bytes, int]:
        counter = self.send_counter
        nonce = build_nonce(counter)
        aad = build_aad(
            self.sender_id,
            self.receiver_id,
            self.alice_sid,
            self.bob_sid,
            counter,
        )
        ciphertext = self._aes.encrypt(nonce, plaintext, aad)
        self.send_counter += 1
        return ciphertext, nonce, aad, counter

    def decrypt(self, ciphertext: bytes, counter: int) -> bytes:
        if counter != self.recv_counter:
            raise ValueError(
                f"replay/stale counter: expected {self.recv_counter}, got {counter}"
            )
        nonce = build_nonce(counter)
        aad = build_aad(
            self.sender_id,
            self.receiver_id,
            self.alice_sid,
            self.bob_sid,
            counter,
        )
        try:
            plaintext = self._aes.decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise ValueError("AEAD verification failed") from exc
        self.recv_counter += 1
        return plaintext
