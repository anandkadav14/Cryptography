"""
Receiver Server
Listens for protected application records and validates/decrypts them.
"""

import json
import sys
import os
import logging

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.crypto_engine import CryptoEngine, AuthenticationError
from shared.replay_detector import ReplayDetector
from shared.aad_utils import aad_matches_sequence
from shared.config import *


class ReceiverServer:
    """
    Server that receives and validates protected application records.
    Handles authentication verification and replay detection.
    """

    def __init__(self, algorithm=ALGORITHM_AES_GCM, key=None, host=SERVER_HOST, port=SERVER_PORT):
        """
        Initialize receiver server.

        Args:
            algorithm: AEAD algorithm to use
            key: shared secret key (if None, will be generated)
            host: server host (default: localhost)
            port: server port (default: 5000)
        """
        self.algorithm = algorithm
        self.crypto_engine = CryptoEngine(algorithm, key)
        self.shared_key = self.crypto_engine.get_key()
        self.replay_detector = ReplayDetector()
        self.host = host
        self.port = port
        self.running = False
        self.records_received = 0
        self.records_verified = 0
        self.records_failed = 0

        # Setup logging
        self.setup_logging()
        self.logger.info(f"ReceiverServer initialized with {algorithm}")
        self.logger.info(f"Shared Key: {self.crypto_engine.export_key_hex()[:16]}...")

    def setup_logging(self):
        """Setup logging for server operations."""
        self.logger = logging.getLogger(__name__)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s [SERVER] %(levelname)s: %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def process_protected_record(self, protected_record_json):
        """
        Process an incoming protected application record.

        Args:
            protected_record_json: JSON string with record data

        Returns:
            dict: {
                'success': bool,
                'plaintext': str (if successful),
                'error': str (if failed),
                'replay': bool,
                'sequence': int,
                'algorithm': str,
                'aad': str
            }
        """
        try:
            # Parse JSON
            record = json.loads(protected_record_json)
            self.records_received += 1

            # Extract fields
            nonce_hex = record.get('nonce')
            ciphertext_hex = record.get('ciphertext')
            tag_hex = record.get('tag')
            aad_hex = record.get('aad', '')
            sequence = record.get('sequence', -1)
            algorithm = record.get('algorithm')

            # Validate algorithm
            if algorithm != self.algorithm:
                return self._error_response(
                    f"Algorithm mismatch: expected {self.algorithm}, got {algorithm}"
                )

            # Convert from hex
            nonce = bytes.fromhex(nonce_hex)
            ciphertext = bytes.fromhex(ciphertext_hex)
            tag = bytes.fromhex(tag_hex)
            aad = bytes.fromhex(aad_hex) if aad_hex else b''

            # ===== STEP 1: Replay Detection (check only; commit after auth) =====
            self.logger.info(f"[Sequence {sequence}] Checking for replay...")
            replay_result = self.replay_detector.check(sequence)
            if replay_result['is_replay']:
                self.records_failed += 1
                self.logger.warning(f"[Sequence {sequence}] REPLAY DETECTED: {replay_result['message']}")
                return self._error_response(
                    replay_result['message'],
                    is_replay=True,
                    sequence=sequence
                )

            # Sequence in JSON must match sequence bound inside AAD
            if not aad_matches_sequence(aad, sequence):
                self.records_failed += 1
                self.logger.error(f"[Sequence {sequence}] ✗ AAD sequence binding mismatch")
                return self._error_response(
                    "Authentication verification failed: AAD sequence binding mismatch",
                    sequence=sequence
                )

            # ===== STEP 2: Authentication Verification =====
            self.logger.info(f"[Sequence {sequence}] Verifying authentication...")
            try:
                plaintext = self.crypto_engine.decrypt(ciphertext, tag, nonce, aad)
                # ===== Commit replay state only after successful auth =====
                self.replay_detector.register(sequence)
                self.records_verified += 1
                self.logger.info(f"[Sequence {sequence}] ✓ Authentication verified")

                # ===== STEP 3: Return recovered plaintext =====
                self.logger.info(f"[Sequence {sequence}] Plaintext recovered successfully")
                return {
                    'success': True,
                    'plaintext': plaintext.decode('utf-8', errors='replace'),
                    'sequence': sequence,
                    'algorithm': algorithm,
                    'aad': aad.hex(),
                    'message': 'Record validated and decrypted successfully'
                }

            except AuthenticationError as e:
                self.records_failed += 1
                self.logger.error(f"[Sequence {sequence}] ✗ Authentication FAILED: {str(e)}")
                return self._error_response(
                    f"Authentication verification failed: {str(e)}",
                    sequence=sequence
                )

        except json.JSONDecodeError as e:
            self.records_failed += 1
            self.logger.error(f"JSON decode error: {str(e)}")
            return self._error_response(f"Invalid JSON format: {str(e)}")
        except Exception as e:
            self.records_failed += 1
            self.logger.error(f"Unexpected error: {str(e)}")
            return self._error_response(f"Unexpected error: {str(e)}")

    def _error_response(self, error_message, is_replay=False, sequence=-1):
        """Create an error response."""
        return {
            'success': False,
            'error': error_message,
            'replay': is_replay,
            'sequence': sequence,
            'message': 'Record validation failed - plaintext NOT released'
        }

    def get_statistics(self):
        """Return server statistics."""
        return {
            'algorithm': self.algorithm,
            'records_received': self.records_received,
            'records_verified': self.records_verified,
            'records_failed': self.records_failed,
            'success_rate': (self.records_verified / self.records_received * 100) if self.records_received > 0 else 0,
            'replay_window_state': self.replay_detector.export_state()
        }

    def get_shared_key_hex(self):
        """Return shared key in hex format (for client to use)."""
        return self.crypto_engine.export_key_hex()

    def set_algorithm(self, algorithm):
        """Change the AEAD algorithm."""
        if algorithm not in [ALGORITHM_AES_GCM, ALGORITHM_CHACHA20]:
            raise ValueError(f"Invalid algorithm: {algorithm}")
        self.algorithm = algorithm
        self.crypto_engine = CryptoEngine(algorithm, self.shared_key)
        self.logger.info(f"Algorithm switched to {algorithm}")

    def reset_replay_detector(self):
        """Reset replay detector (for testing)."""
        self.replay_detector.reset()
        self.logger.info("Replay detector reset")

    def reset_statistics(self):
        """Reset statistics counters."""
        self.records_received = 0
        self.records_verified = 0
        self.records_failed = 0
        self.logger.info("Statistics reset")
