# CS6530 Assignment 1: Secure Data Protection using AES-GCM and ChaCha20-Poly1305

## Project Overview

This project implements a **secure data protection subsystem** for generic chunked/packetized application records using modern Authenticated Encryption with Associated Data (AEAD) techniques.

### Supported Algorithms
- **AES-GCM** (Advanced Encryption Standard - Galois/Counter Mode)
- **ChaCha20-Poly1305** (ChaCha20 stream cipher with Poly1305 authentication)

### Project Structure

```
Assignment_one/
├── shared/                          # Shared cryptography utilities (both use)
│   ├── __init__.py
│   ├── config.py                    # Configuration & constants
│   ├── crypto_engine.py             # AES-GCM & ChaCha20-Poly1305 wrapper
│   ├── nonce_manager.py             # Unique nonce generation
│   └── replay_detector.py           # Replay detection (sliding window)
│
├── server/                          # Receiver side
│   ├── __init__.py
│   ├── server.py                    # ReceiverServer class
│   └── README_SERVER.md
│
├── client/                          # Sender side
│   ├── __init__.py
│   ├── client.py                    # SenderClient class
│   ├── test_harness.py              # All 8 tests (TR-1 to TR-8)
│   └── README_CLIENT.md
│
├── requirements.txt                 # Python dependencies
└── README.md                        # This file
```

---

## Software Requirements

- **Python**: 3.8 or higher
- **Cryptography Library**: cryptography >= 41.0.0

---

## Installation & Setup

### 1. Install Python Dependencies

```bash
cd "/home/anandc2/Desktop/Crptography Assignment /Crptography/Assignment_one"
pip install -r requirements.txt
```

### 2. Verify Installation

```bash
python3 -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305; print('✓ Cryptography library installed')"
```

---

## Quick Start

### Run All Tests (Both Algorithms)

```bash
cd "/home/anandc2/Desktop/Crptography Assignment /Crptography/Assignment_one"
python3 client/test_harness.py
```

This will execute all 8 testing requirements (TR-1 to TR-8) for both AES-GCM and ChaCha20-Poly1305.

---

## Testing Requirements

The test suite demonstrates compliance with the following requirements:

| Test | Description | Expected Result |
|------|-------------|-----------------|
| **TR-1** | Positive Baseline Test | Record encrypted → transmitted → verified → decrypted successfully |
| **TR-2** | Ciphertext Integrity Test | Modified ciphertext → authentication failure → rejection |
| **TR-3** | Authentication Tag Test | Modified tag → authentication failure → rejection |
| **TR-4** | Associated Data (AAD) Test | Modified AAD → authentication failure → rejection |
| **TR-5** | Replay Test | Duplicate record → replay detected → rejection |
| **TR-6** | Wrong-Key Test | Wrong key used → authentication failure → rejection |
| **TR-7** | Nonce Management Verification | 10,000 records processed → all nonces unique → no reuse |
| **TR-8** | Performance Evaluation | Measure & compare both algorithms for 64B, 1KB, 64KB records |

---

## Key Components

### 1. Shared Crypto Engine (`shared/crypto_engine.py`)

Unified AEAD wrapper supporting both algorithms:

```python
from shared.crypto_engine import CryptoEngine

# Create engine with AES-GCM
engine = CryptoEngine(algorithm="AES-GCM")

# Encrypt
result = engine.encrypt(plaintext, nonce, aad)
# Returns: {ciphertext, tag}

# Decrypt & Verify
plaintext = engine.decrypt(ciphertext, tag, nonce, aad)
# Raises AuthenticationError if verification fails
```

### 2. Nonce Manager (`shared/nonce_manager.py`)

Ensures no nonce reuse:

```python
from shared.nonce_manager import NonceManager

manager = NonceManager()
nonce = manager.generate_nonce()  # Returns 12-byte unique nonce
```

**Nonce Generation Strategy:**
- 4-byte random prefix
- 8-byte incremental counter
- Guarantees uniqueness: 2^64 nonces per key

### 3. Replay Detector (`shared/replay_detector.py`)

Detects replayed records using sliding window:

```python
from shared.replay_detector import ReplayDetector

detector = ReplayDetector(window_size=10000)
result = detector.check_and_update(sequence_number)
# Returns: {is_replay, is_out_of_order, message}
```

### 4. Sender Client (`client/client.py`)

Encrypts and protects records:

```python
from client.client import SenderClient

sender = SenderClient(algorithm="AES-GCM")

# Protect a record
protected = sender.protect_record(
    plaintext="Hello, World!",
    aad="metadata:user"
)

# Serialize to JSON for transmission
json_str = sender.send_record(protected)
```

### 5. Receiver Server (`server/server.py`)

Validates, decrypts, and recovers records:

```python
from server.server import ReceiverServer

receiver = ReceiverServer(algorithm="AES-GCM", key=shared_key)

# Process incoming record
response = receiver.process_protected_record(json_record_str)

if response['success']:
    plaintext = response['plaintext']
else:
    print(f"Validation failed: {response['error']}")
```

---

## Record Format

### Protected Application Record (JSON)

```json
{
  "sequence": 0,
  "nonce": "a1b2c3d4e5f6a1b2c3d4e5f6",
  "ciphertext": "encrypted_data_hex",
  "tag": "authentication_tag_hex",
  "aad": "associated_data_hex",
  "algorithm": "AES-GCM",
  "plaintext_length": 13
}
```

### Processing Pipeline (Sender)

```
Application Record
    ↓
Record Processing
    ↓
Nonce Generation (unique, non-repeating)
    ↓
AAD Binding (metadata authentication)
    ↓
AEAD Encryption (AES-GCM or ChaCha20)
    ↓
Protected Record (serialized JSON)
```

### Processing Pipeline (Receiver)

```
Protected Record (JSON)
    ↓
Replay Verification (sequence check)
    ↓
Authentication Verification (tag validation)
    ↓
Decryption (plaintext recovery)
    ↓
Recovered Application Record
```

---

## Performance Characteristics

### Test Sizes
- **64 Bytes**: Small message (e.g., sensor reading)
- **1 KiB**: Typical small packet
- **64 KiB**: Large payload (media chunk)

### Metrics Collected
- Encryption time (milliseconds)
- Decryption time (milliseconds)
- Total time (encrypt + decrypt)
- Throughput (MB/s)

---

## Security Features

1. **Authenticated Encryption**: Both ciphertext and metadata are protected
2. **Nonce Management**: Prevents nonce reuse attacks
3. **Replay Detection**: Sliding window detects repeated/reordered records
4. **AAD Protection**: Associated data integrity verified
5. **Strict Failure Handling**: Failed records are never released as plaintext

---

## Implementation Notes

### Nonce Management Strategy (SR-3)
- Uses 12-byte nonce (96 bits) - recommended for both AES-GCM and ChaCha20
- Counter-based approach: 4-byte random prefix + 8-byte counter
- Supports up to 2^64 unique nonces per key
- Suitable for long-lived keys in single-party scenario

### Replay Handling Strategy (FR-8)
- Sliding window approach with sequence numbers
- Window size: configurable (default 10,000)
- Detects duplicate and out-of-order records
- Prevents both replay and reordering attacks

### Associated Data (AAD) Selection
- Optional per-record metadata (e.g., user ID, timestamp)
- Included in authentication but NOT encrypted
- Ensures integrity of record metadata
- Example: `"user:alice:timestamp:2026-08-15"`

---

## Example Usage

### Running a Single Test

```bash
python3 -c "
from client.test_harness import TestHarness

# Test with AES-GCM
harness = TestHarness(algorithm='AES-GCM')
harness.run_tr1_positive_baseline()
"
```

### Processing 10,000 Records (TR-7)

```bash
python3 -c "
from client.test_harness import TestHarness

harness = TestHarness(algorithm='AES-GCM')
harness.run_tr7_nonce_management()
"
```

---

## Debugging

Enable detailed logging:

```bash
export PYTHONUNBUFFERED=1
python3 client/test_harness.py 2>&1 | tee test_output.log
```

---

## Expected Output

```
======================================================================
Test Harness Initialized
Algorithm: AES-GCM
Shared Key: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d...
======================================================================

──────────────────────────────────────────────────────────────────────
TR-1: Positive Baseline Test
Description: Valid record protection, transmission, and recovery
──────────────────────────────────────────────────────────────────────

1. Sender protecting record...
   Plaintext: Hello, World! This is a test message.
   AAD: metadata:test

2. Receiver processing record...
   Decrypted plaintext: Hello, World! This is a test message.
✓ PASS Record recovered successfully

[... more tests ...]

======================================================================
TEST RESULTS SUMMARY FOR AES-GCM
======================================================================
TR-1: PASS
TR-2: PASS
TR-3: PASS
TR-4: PASS
TR-5: PASS
TR-6: PASS
TR-7: PASS
TR-8: PASS

Total: 8/8 tests passed (100.0%)
======================================================================
```

---

## Troubleshooting

### "ModuleNotFoundError: No module named 'cryptography'"

```bash
pip install cryptography>=41.0.0
```

### "Authentication verification failed"

- Verify nonce matches what was used during encryption
- Verify AAD matches exactly
- Verify the same key is used for both encryption and decryption
- Check that ciphertext and tag were not modified

### Slow Performance

- Check system load
- Ensure no antivirus software is scanning files
- ChaCha20 typically faster than AES-GCM on systems without AES-NI support

---

## File Structure Summary

```
shared/
├── crypto_engine.py      → AESGCM, ChaCha20Poly1305 wrapper
├── nonce_manager.py      → Counter-based unique nonce generation
└── replay_detector.py    → Sliding window replay detection

server/
└── server.py             → ReceiverServer (decrypt, verify, replay check)

client/
├── client.py             → SenderClient (encrypt, nonce gen, AAD)
└── test_harness.py       → TR-1 to TR-8 test suite
```

---

## Authors

CS6530 Assignment 1 - IIT Madras
August 2026

---

## References

- [NIST SP 800-38D: GALOIS/COUNTER MODE (GCM)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [ChaCha20 and Poly1305 (RFC 8439)](https://tools.ietf.org/html/rfc8439)
- [cryptography.io Documentation](https://cryptography.io/)
