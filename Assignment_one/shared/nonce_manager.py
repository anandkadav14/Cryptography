"""
Nonce Management Module
Ensures unique nonce generation without reuse.
"""

import os
from .config import NONCE_SIZE_AES_GCM


class NonceManager:
    """
    Manages nonce generation to prevent reuse.
    Uses a counter-based approach for guaranteed uniqueness.
    """

    def __init__(self):
        """
        Initialize nonce manager.
        Uses random prefix + counter for uniqueness.
        Counter starts at random value for session privacy.
        """
        # 4-byte random prefix
        self.prefix = os.urandom(4)
        # Counter starts at random value (0 to 2^32-1) for session privacy
        # This ensures different sessions don't use predictable nonce sequences
        self.counter = int.from_bytes(os.urandom(4), byteorder='big')
        # Track all generated nonces (for verification)
        self.generated_nonces = set()

    def generate_nonce(self):
        """
        Generate a unique nonce.
        Format: 4-byte prefix (random) + 8-byte counter (incremental)

        Returns:
            bytes: 12-byte nonce
        """
        # Ensure counter doesn't overflow
        if self.counter >= 2**64:
            raise RuntimeError("Nonce counter overflow - too many nonces generated")

        # Create nonce: prefix (4 bytes) + counter (8 bytes)
        counter_bytes = self.counter.to_bytes(8, byteorder='big')
        nonce = self.prefix + counter_bytes

        # Verify nonce size
        if len(nonce) != NONCE_SIZE_AES_GCM:
            raise RuntimeError(f"Nonce size mismatch: expected {NONCE_SIZE_AES_GCM}, got {len(nonce)}")

        # Track nonce
        self.generated_nonces.add(nonce.hex())

        # Increment counter
        self.counter += 1

        return nonce

    def get_nonce_count(self):
        """Return the number of nonces generated so far."""
        return self.counter

    def has_nonce_been_used(self, nonce):
        """
        Check if a nonce has been generated before.

        Args:
            nonce: bytes to check

        Returns:
            bool: True if nonce was previously generated
        """
        return nonce.hex() in self.generated_nonces

    def reset(self):
        """Reset nonce manager (for testing purposes)."""
        self.prefix = os.urandom(4)
        self.counter = 0
        self.generated_nonces.clear()

    def export_state(self):
        """Export nonce manager state (for debugging)."""
        return {
            'prefix': self.prefix.hex(),
            'counter': self.counter,
            'nonces_generated': len(self.generated_nonces)
        }
