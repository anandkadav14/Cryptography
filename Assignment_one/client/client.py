"""
Sender Client
Encrypts application records and sends them to the receiver.
"""

import json
import sys
import os
import logging

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.crypto_engine import CryptoEngine
from shared.nonce_manager import NonceManager
from shared.aad_utils import build_record_aad
from shared.config import *


class SenderClient:
    """
    Client that encrypts and sends protected application records.
    Manages nonce generation and record formatting.
    """

    def __init__(self, algorithm=ALGORITHM_AES_GCM, key=None):
        """
        Initialize sender client.

        Args:
            algorithm: AEAD algorithm to use
            key: shared secret key (if None, will be generated)
        """
        self.algorithm = algorithm
        self.crypto_engine = CryptoEngine(algorithm, key)
        self.shared_key = self.crypto_engine.get_key()
        self.nonce_manager = NonceManager()
        self.sequence_number = 0
        self.records_sent = 0
        self.records_protected = 0

        # Setup logging
        self.setup_logging()
        self.logger.info(f"SenderClient initialized with {algorithm}")
        self.logger.info(f"Shared Key: {self.crypto_engine.export_key_hex()[:16]}...")

    def setup_logging(self):
        """Setup logging for client operations."""
        self.logger = logging.getLogger(__name__)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s [CLIENT] %(levelname)s: %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def protect_record(self, plaintext, aad=None):
        """
        Protect an application record using AEAD.

        Args:
            plaintext: str or bytes to encrypt
            aad: associated data string (optional)

        Returns:
            dict: protected record with nonce, ciphertext, tag, etc.
        """
        # Convert plaintext to bytes
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode('utf-8')
        else:
            plaintext_bytes = plaintext

        # Generate nonce
        nonce = self.nonce_manager.generate_nonce()
        self.logger.info(f"[Seq {self.sequence_number}] Generated nonce: {nonce.hex()}")

        # Prepare user AAD, then bind sequence into canonical AAD for AEAD
        if aad is None:
            user_aad_bytes = b''
        elif isinstance(aad, str):
            user_aad_bytes = aad.encode('utf-8')
        else:
            user_aad_bytes = aad

        aad_bytes = build_record_aad(self.sequence_number, user_aad_bytes)
        aad_hex = aad_bytes.hex()

        # Encrypt
        self.logger.info(f"[Seq {self.sequence_number}] Encrypting with {self.algorithm}...")
        result = self.crypto_engine.encrypt(plaintext_bytes, nonce, aad_bytes)

        # Create protected record
        protected_record = {
            'sequence': self.sequence_number,
            'nonce': nonce.hex(),
            'ciphertext': result['ciphertext'].hex(),
            'tag': result['tag'].hex(),
            'aad': aad_hex,
            'algorithm': self.algorithm,
            'plaintext_length': len(plaintext_bytes)
        }

        self.records_protected += 1
        self.logger.info(f"[Seq {self.sequence_number}] ✓ Record protected (ciphertext size: {len(result['ciphertext'])} bytes)")

        self.sequence_number += 1
        return protected_record

    def send_record(self, protected_record):
        """
        Prepare record as JSON for transmission.

        Args:
            protected_record: dict with protected record data

        Returns:
            str: JSON representation
        """
        json_data = json.dumps(protected_record)
        self.records_sent += 1
        return json_data

    def create_tampered_ciphertext(self, protected_record):
        """
        Create a tampered version of the record (flip bits in ciphertext).
        For TR-2: Ciphertext Integrity Test
        """
        tampered = dict(protected_record)
        ciphertext = bytes.fromhex(tampered['ciphertext'])

        # Flip the first byte
        if len(ciphertext) > 0:
            tampered_ciphertext = bytearray(ciphertext)
            tampered_ciphertext[0] ^= 0xFF  # Flip all bits in first byte
            tampered['ciphertext'] = bytes(tampered_ciphertext).hex()
            self.logger.info(f"[Seq {protected_record['sequence']}] Created tampered ciphertext")

        return tampered

    def create_tampered_tag(self, protected_record):
        """
        Create a tampered version with modified tag.
        For TR-3: Authentication Tag Test
        """
        tampered = dict(protected_record)
        tag = bytes.fromhex(tampered['tag'])

        if len(tag) > 0:
            tampered_tag = bytearray(tag)
            tampered_tag[0] ^= 0xFF  # Flip bits
            tampered['tag'] = bytes(tampered_tag).hex()
            self.logger.info(f"[Seq {protected_record['sequence']}] Created tampered tag")

        return tampered

    def create_tampered_aad(self, protected_record):
        """
        Create a tampered version with modified AAD.
        For TR-4: Associated Data Test
        """
        tampered = dict(protected_record)

        if tampered['aad']:
            old_aad = bytes.fromhex(tampered['aad'])
            # Modify AAD by flipping first byte
            tampered_aad = bytearray(old_aad)
            if len(tampered_aad) > 0:
                tampered_aad[0] ^= 0xFF
            tampered['aad'] = bytes(tampered_aad).hex()
            self.logger.info(f"[Seq {protected_record['sequence']}] Created tampered AAD")
        else:
            # If no AAD, add one
            tampered['aad'] = b"INJECTED_AAD".hex()
            self.logger.info(f"[Seq {protected_record['sequence']}] Injected AAD")

        return tampered

    def create_wrong_key_record(self, protected_record):
        """
        Create a version encrypted with wrong key.
        For TR-6: Wrong-Key Test
        """
        # Generate a different key
        wrong_key = os.urandom(KEY_SIZE)
        wrong_engine = CryptoEngine(self.algorithm, wrong_key)

        # Re-encrypt with wrong key
        nonce = bytes.fromhex(protected_record['nonce'])
        plaintext = protected_record.get('original_plaintext', b'').encode() if isinstance(protected_record.get('original_plaintext'), str) else b'test'
        aad = bytes.fromhex(protected_record['aad']) if protected_record['aad'] else b''

        result = wrong_engine.encrypt(plaintext, nonce, aad)

        wrong_record = dict(protected_record)
        wrong_record['ciphertext'] = result['ciphertext'].hex()
        wrong_record['tag'] = result['tag'].hex()

        self.logger.info(f"[Seq {protected_record['sequence']}] Created record with wrong key")
        return wrong_record

    def set_algorithm(self, algorithm):
        """Change the AEAD algorithm."""
        if algorithm not in [ALGORITHM_AES_GCM, ALGORITHM_CHACHA20]:
            raise ValueError(f"Invalid algorithm: {algorithm}")
        self.algorithm = algorithm
        self.crypto_engine = CryptoEngine(algorithm, self.shared_key)
        self.logger.info(f"Algorithm switched to {algorithm}")

    def reset_nonce_manager(self):
        """Reset nonce manager (for testing)."""
        self.nonce_manager.reset()
        self.logger.info("Nonce manager reset")

    def reset_sequence(self):
        """Reset sequence number."""
        self.sequence_number = 0
        self.logger.info("Sequence number reset")

    def get_shared_key_hex(self):
        """Return shared key (to give to server)."""
        return self.crypto_engine.export_key_hex()

    def set_shared_key(self, key_hex):
        """Set shared key from hex."""
        self.crypto_engine.import_key_hex(key_hex)
        self.shared_key = self.crypto_engine.get_key()
        self.logger.info("Shared key updated")

    def get_statistics(self):
        """Return client statistics."""
        return {
            'algorithm': self.algorithm,
            'records_protected': self.records_protected,
            'records_sent': self.records_sent,
            'sequence_number': self.sequence_number,
            'nonce_count': self.nonce_manager.get_nonce_count()
        }
