"""Configuration and constants for the secure data protection subsystem."""

# AEAD Algorithm Types
ALGORITHM_AES_GCM = "AES-GCM"
ALGORITHM_CHACHA20 = "ChaCha20-Poly1305"

# Key Size (256 bits)
KEY_SIZE = 32

# Nonce Sizes
NONCE_SIZE_AES_GCM = 12  # 96 bits for AES-GCM
NONCE_SIZE_CHACHA20 = 12  # 96 bits for ChaCha20-Poly1305

# Authentication Tag Size (128 bits)
TAG_SIZE = 16

# Replay Detection Window Size
REPLAY_WINDOW_SIZE = 10000

# Server Configuration
SERVER_HOST = "localhost"
SERVER_PORT = 5000

# Test Record Sizes (for TR-8 performance evaluation)
TEST_RECORD_SIZES = [64, 1024, 65536]  # 64 Bytes, 1 KiB, 64 KiB

# Number of records for nonce management test (TR-7)
NONCE_TEST_COUNT = 10000
