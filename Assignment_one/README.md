# CS6530 Assignment 1: Secure Data Protection using AES-GCM and ChaCha20-Poly1305

## 📋 Project Overview

This project implements a **secure data protection subsystem** for generic chunked/packetized application records using modern Authenticated Encryption with Associated Data (AEAD) techniques.

### ✅ Features

- **Two AEAD Algorithms**: AES-GCM and ChaCha20-Poly1305
- **Interactive CLI**: User-friendly menu-driven interface for manual testing
- **Smart Nonce Generation**: Random starting counter + sequential increments per session
- **Replay Detection**: Sliding window approach (10,000 record capacity)
- **Associated Data (AAD)**: Optional per-record metadata authentication
- **Comprehensive Testing**: All 8 requirements (TR-1 to TR-8) with pass/fail indicators

---

## 📁 Folder Structure

```
Assignment_one/
│
├── 📂 shared/                          ⭐ Shared Cryptography Utilities
│   ├── __init__.py
│   ├── config.py                       Configuration & constants
│   ├── crypto_engine.py                AES-GCM & ChaCha20-Poly1305 wrapper
│   ├── nonce_manager.py                Unique nonce generation (random start + counter)
│   └── replay_detector.py              Replay detection (sliding window)
│
├── 📂 server/                          👤 Receiver Side
│   ├── __init__.py
│   └── server.py                       ReceiverServer class (decrypt & verify)
│
├── 📂 client/                          👤 Sender Side
│   ├── __init__.py
│   └── client.py                       SenderClient class (encrypt & protect)
│
├── 📂 venv/                            Python virtual environment
│
├── main.py                             ⭐ Interactive CLI (main interface)
├── requirements.txt                    Python dependencies
├── .gitignore                          Git ignore file
├── README.md                           This file
├── SETUP.md                            Quick setup guide
└── run_tests.sh                        Test execution script

```

---

## 🚀 Quick Start (5 minutes)

### Step 1: Install Dependencies

```bash
cd "/home/anandc2/Desktop/Crptography Assignment /Crptography/Assignment_one"
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 2: Run Interactive CLI

```bash
python3 main.py
```

### Step 3: Test the System

The interactive menu will appear:

```
======================================================================
  SECURE DATA PROTECTION SUBSYSTEM
======================================================================

Menu Options:
  1. Select/Change Algorithm
  2. Encrypt Record (Sender)
  3. Decrypt Record (Receiver)
  4. Tamper with Record (Malicious Actor)
  5. Test: Wrong Key (TR-6)
  6. Test: Nonce Uniqueness (TR-7)
  7. Test: Performance Evaluation (TR-8)
  8. View Shared Key (for TR-6 testing)
  9. Exit

Enter choice (1-9):
```

---

## 📊 How to Use

### Workflow 1: Basic Encryption/Decryption (TR-1)

```
1. Select Algorithm (AES-GCM or ChaCha20)
   ↓
2. Encrypt Record → Enter plaintext + AAD
   ↓
3. Copy the JSON output
   ↓
4. Decrypt Record → Paste the JSON
   ↓
5. Verify plaintext matches original ✓
```

### Workflow 2: Test with Wrong Key (TR-6)

```
1. Select Algorithm
   ↓
2. Encrypt a record
   ↓
3. View Shared Key (option 8) → Copy the full 64-char hex key
   ↓
4. Test Wrong Key (option 5)
   ↓
5. Choose: 
   - Option 1: Test with CORRECT key → Should succeed ✓
   - Option 2: Test with WRONG key (auto-generated) → Should fail ✗
   - Option 3: Test with CUSTOM key → Paste hex key to test
```

### Workflow 3: Test Nonce Uniqueness (TR-7)

```
1. Select Algorithm
   ↓
2. Test Nonce Uniqueness (option 6)
   ↓
3. Enter number of records (default 100)
   ↓
4. System generates records and verifies all nonces are unique
   ↓
5. Result: ✓ PASSED - All 100 nonces unique
```

### Workflow 4: Performance Comparison (TR-8)

```
1. Select Algorithm (AES-GCM)
   ↓
2. Test Performance (option 7)
   ↓
3. See results for 64B, 1KB, 64KB
   ↓
4. Repeat with ChaCha20-Poly1305
   ↓
5. Compare throughput and latency
```

---

## 🔐 Supported Algorithms

### AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)

- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 96 bits (12 bytes)
- **Tag Size**: 128 bits (16 bytes)
- **Best for**: General purpose, hardware acceleration available

### ChaCha20-Poly1305 (Stream Cipher + Poly1305)

- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 96 bits (12 bytes)
- **Tag Size**: 128 bits (16 bytes)
- **Best for**: Software implementations, no hardware dependencies

---

## 📝 Testing Requirements

All 8 requirements are integrated into the interactive CLI:

| Test | CLI Option | Description | Expected Result |
|------|-----------|-------------|-----------------|
| **TR-1** | Options 2-3 | Encrypt & decrypt | Plaintext matches original ✓ |
| **TR-2** | Option 4 (ciphertext) | Tamper with ciphertext | Rejected ✗ |
| **TR-3** | Option 4 (tag) | Tamper with authentication tag | Rejected ✗ |
| **TR-4** | Option 4 (AAD) | Tamper with associated data | Rejected ✗ |
| **TR-5** | Option 4 (replay) | Send same record twice | 2nd rejected as replay ✗ |
| **TR-6** | Option 5 | Decrypt with wrong key | Authentication fails ✗ |
| **TR-7** | Option 6 | Generate 100+ records | All nonces unique ✓ |
| **TR-8** | Option 7 | Measure performance | Display throughput (MB/s) |

---

## 🔑 Key Components

### 1. Nonce Generation (Smart Counter-Based)

**Design**: Random Prefix + Randomized Starting Counter

```
Session 1: [Random Prefix] + [Random Start (e.g., 78)] → 79, 80, 81...
Session 2: [Random Prefix] + [Random Start (e.g., 4521)] → 4522, 4523...
Session 3: [Random Prefix] + [Random Start (e.g., 99)] → 100, 101...
```

**Benefits**:
- ✅ Each session looks different (random start)
- ✅ Within session nonces are predictable (sequential)
- ✅ Guaranteed uniqueness (2^64 nonces per key)
- ✅ No collision risk
- ✅ NIST compliant

### 2. Crypto Engine

Unified wrapper for both AEAD algorithms:

```python
from shared.crypto_engine import CryptoEngine

engine = CryptoEngine(algorithm="AES-GCM")
result = engine.encrypt(plaintext, nonce, aad)  # Returns: {ciphertext, tag}
plaintext = engine.decrypt(ciphertext, tag, nonce, aad)
```

### 3. Replay Detector

Sliding window detection:

```python
from shared.replay_detector import ReplayDetector

detector = ReplayDetector(window_size=10000)
result = detector.check_and_update(sequence_number)
# {is_replay: bool, message: str}
```

### 4. Sender Client

Protects application records:

```python
from client.client import SenderClient

sender = SenderClient(algorithm="AES-GCM")
protected = sender.protect_record(
    plaintext="Hello, World!",
    aad="user:alice"
)
```

### 5. Receiver Server

Validates and decrypts:

```python
from server.server import ReceiverServer

receiver = ReceiverServer(algorithm="AES-GCM", key=shared_key)
response = receiver.process_protected_record(json_record)

if response['success']:
    plaintext = response['plaintext']
```

---

## 📦 Protected Record Format

### JSON Structure

```json
{
  "sequence": 0,
  "nonce": "e5abc78600000000a0119b81",
  "ciphertext": "d59028b3e08b3824101c2c",
  "tag": "6c63af7565bf016084be8d96a18cdd2b",
  "aad": "7072613a616e61",
  "algorithm": "AES-GCM",
  "plaintext_length": 11
}
```

### Processing Pipelines

**Sender (Encrypt)**:
```
Plaintext + AAD
    ↓
Generate Unique Nonce
    ↓
Encrypt with AEAD
    ↓
Generate Auth Tag
    ↓
Protected Record (JSON)
```

**Receiver (Decrypt)**:
```
Protected Record (JSON)
    ↓
Replay Check (sequence number)
    ↓
Verify Auth Tag
    ↓
Decrypt Ciphertext
    ↓
Plaintext
```

---

## 🧪 Testing Guide

### Test Both Algorithms Separately

```bash
# Terminal 1: Test AES-GCM
python3 main.py
→ Select option 1: AES-GCM
→ Run all tests (options 2-7)
→ Take screenshots for report

# Terminal 2: Test ChaCha20
python3 main.py
→ Select option 1: ChaCha20-Poly1305
→ Run all tests (options 2-7)
→ Compare performance with AES-GCM
```

### Example Test Session

```
$ python3 main.py

[Welcome message]

Enter choice (1-9): 1
→ Select AES-GCM

Enter choice (1-9): 2
→ Encrypt Record
→ Enter plaintext: "Hello World"
→ Enter AAD: "metadata"
→ Output: JSON protected record

Enter choice (1-9): 3
→ Decrypt Record
→ Paste: [JSON from above]
→ Output: "Hello World" ✓

Enter choice (1-9): 6
→ Test Nonce Uniqueness (TR-7)
→ Generate 100 records
→ ✓ All 100 nonces unique

Enter choice (1-9): 7
→ Performance Evaluation (TR-8)
→ 64B:   0.21 ms, throughput: 0.29 MB/s
→ 1KB:   0.08 ms, throughput: 11.74 MB/s
→ 64KB:  0.40 ms, throughput: 157.25 MB/s
```

---

## 📊 Performance Characteristics

Test data shows AES-GCM performance:

| Size | Encrypt (ms) | Decrypt (ms) | Total (ms) | Throughput |
|------|------------|------------|-----------|-----------|
| 64B | 0.147 | 0.061 | 0.207 | 0.29 MB/s |
| 1KB | 0.039 | 0.044 | 0.083 | 11.74 MB/s |
| 64KB | 0.174 | 0.224 | 0.397 | 157.25 MB/s |

**Note**: Performance varies by system. Use option 7 to measure your system.

---

## 🔒 Security Features

1. **Authenticated Encryption**: Ciphertext + metadata protection
2. **Unique Nonces**: Random start + counter = no reuse risk
3. **Replay Detection**: Sequence tracking prevents replays
4. **AAD Binding**: Metadata integrity verified
5. **Strict Failure**: Never release plaintext on auth failure
6. **Algorithm Agility**: Switch between AES-GCM and ChaCha20

---

## 🐛 Troubleshooting

### "ModuleNotFoundError: No module named 'cryptography'"

```bash
source venv/bin/activate
pip install cryptography>=41.0.0
```

### "Cannot find venv"

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### "Authentication verification failed"

Check:
- ✓ Same key used for encryption and decryption
- ✓ Nonce matches exactly
- ✓ AAD matches (if provided)
- ✓ Ciphertext/tag not modified

### "Nonce starts sequentially"

**This is by design!** Each session:
1. Generates random starting counter value
2. Increments sequentially within session
3. Ensures uniqueness + looks random across sessions

---

## 📚 Files Overview

### Core Cryptography

| File | Lines | Purpose |
|------|-------|---------|
| `shared/crypto_engine.py` | ~150 | AES-GCM & ChaCha20 wrapper |
| `shared/nonce_manager.py` | ~85 | Unique nonce generation |
| `shared/replay_detector.py` | ~100 | Replay detection |
| `shared/config.py` | ~50 | Constants & configuration |

### Sender/Receiver

| File | Lines | Purpose |
|------|-------|---------|
| `client/client.py` | ~240 | SenderClient class |
| `server/server.py` | ~200 | ReceiverServer class |

### Testing & CLI

| File | Lines | Purpose |
|------|-------|---------|
| `main.py` | ~450 | Interactive CLI interface |
| `requirements.txt` | ~3 | Python dependencies |

---

## 💾 Requirements

```
cryptography>=41.0.0
```

Install with:
```bash
pip install -r requirements.txt
```

---

## 🎯 Deliverables

### D1: Source Code ✅
- Complete implementation in `shared/`, `server/`, `client/`
- Interactive CLI in `main.py`
- All tests integrated

### D2: Report (User Responsibility)
- Design summary
- Testing results (TR-1 to TR-8)
- Screenshots from CLI tests
- Performance analysis
- Lessons learned

### D3: README ✅
- This file with complete documentation
- Setup instructions
- Usage examples
- Troubleshooting guide

---

## 🚀 Next Steps

1. **Setup** (5 min):
   ```bash
   cd Assignment_one
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Test** (20 min):
   ```bash
   python3 main.py
   ```

3. **Document** (1-2 hours):
   - Run all tests for AES-GCM
   - Run all tests for ChaCha20-Poly1305
   - Capture screenshots
   - Write report

---

## 📖 References

- [NIST SP 800-38D: GCM](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [ChaCha20 and Poly1305 (RFC 8439)](https://tools.ietf.org/html/rfc8439)
- [cryptography.io Docs](https://cryptography.io/)

---

## ✍️ Authors

**CS6530 - Applied Cryptography - Assignment 1**
IIT Madras | August 2026

---

## 📝 License

Academic Use Only - CS6530 Assignment
