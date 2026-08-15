"""
AEAD Encryption/Decryption Engine
Supports: AES-GCM and ChaCha20-Poly1305
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
import os
import json
from .config import *

class AuthenticationError(Exception):
    """Raised when authentication verification fails."""
    pass


class CryptoEngine:
    """
    Unified AEAD Encryption/Decryption Engine.
    Supports both AES-GCM and ChaCha20-Poly1305.
    """

    def __init__(self, algorithm=ALGORITHM_AES_GCM, key=None):
        """
        Initialize crypto engine with selected algorithm.

        Args:
            algorithm: ALGORITHM_AES_GCM or ALGORITHM_CHACHA20
            key: 32-byte secret key (if None, will be generated)
        """
        if algorithm not in [ALGORITHM_AES_GCM, ALGORITHM_CHACHA20]:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        self.algorithm = algorithm
        self.key = key if key else os.urandom(KEY_SIZE)
        self.cipher = None
        self._initialize_cipher()

    def _initialize_cipher(self):
        """Initialize the cipher object based on selected algorithm."""
        if self.algorithm == ALGORITHM_AES_GCM:
            self.cipher = AESGCM(self.key)
        elif self.algorithm == ALGORITHM_CHACHA20:
            self.cipher = ChaCha20Poly1305(self.key)

    def encrypt(self, plaintext, nonce, aad=None):
        """
        Encrypt plaintext with AEAD.

        Args:
            plaintext: bytes to encrypt
            nonce: unique nonce (bytes)
            aad: associated data (bytes, optional)

        Returns:
            dict: {
                'ciphertext': bytes,
                'tag': bytes (last 16 bytes of ciphertext for AES-GCM),
                'algorithm': str
            }

        Raises:
            ValueError: if nonce size is incorrect
        """
        if len(nonce) != NONCE_SIZE_AES_GCM:
            raise ValueError(f"Nonce size must be {NONCE_SIZE_AES_GCM} bytes, got {len(nonce)}")

        if aad is None:
            aad = b''

        # Encrypt
        ciphertext_with_tag = self.cipher.encrypt(nonce, plaintext, aad)

        # Split ciphertext and tag (last 16 bytes)
        ciphertext = ciphertext_with_tag[:-TAG_SIZE]
        tag = ciphertext_with_tag[-TAG_SIZE:]

        return {
            'ciphertext': ciphertext,
            'tag': tag,
            'algorithm': self.algorithm
        }

    def decrypt(self, ciphertext, tag, nonce, aad=None):
        """
        Decrypt ciphertext with AEAD and verify tag.

        Args:
            ciphertext: bytes to decrypt
            tag: authentication tag (bytes)
            nonce: nonce used during encryption (bytes)
            aad: associated data (bytes, optional)

        Returns:
            bytes: plaintext

        Raises:
            AuthenticationError: if authentication verification fails
        """
        if len(nonce) != NONCE_SIZE_AES_GCM:
            raise ValueError(f"Nonce size must be {NONCE_SIZE_AES_GCM} bytes, got {len(nonce)}")

        if len(tag) != TAG_SIZE:
            raise ValueError(f"Tag size must be {TAG_SIZE} bytes, got {len(tag)}")

        if aad is None:
            aad = b''

        try:
            # Combine ciphertext and tag for decryption
            ciphertext_with_tag = ciphertext + tag
            plaintext = self.cipher.decrypt(nonce, ciphertext_with_tag, aad)
            return plaintext
        except Exception as e:
            raise AuthenticationError(f"Authentication verification failed: {str(e)}")

    def get_key(self):
        """Return the secret key."""
        return self.key

    def set_key(self, key):
        """Set a new secret key."""
        if len(key) != KEY_SIZE:
            raise ValueError(f"Key size must be {KEY_SIZE} bytes, got {len(key)}")
        self.key = key
        self._initialize_cipher()

    def export_key_hex(self):
        """Export key as hexadecimal string."""
        return self.key.hex()

    def import_key_hex(self, hex_key):
        """Import key from hexadecimal string."""
        key = bytes.fromhex(hex_key)
        self.set_key(key)
