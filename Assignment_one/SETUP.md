# 🚀 Quick Setup Guide

## ⚡ Get Started in 2 Minutes

### Step 1: Install Dependencies (30 seconds)

```bash
cd "/home/anandc2/Desktop/Crptography Assignment /Crptography/Assignment_one"
pip install -r requirements.txt
```

### Step 2: Run Tests (1-2 minutes)

```bash
python3 client/test_harness.py
```

**That's it!** ✅

---

## 📊 What You'll See

The test suite will run all **8 testing requirements (TR-1 to TR-8)** for both algorithms:
- ✅ AES-GCM
- ✅ ChaCha20-Poly1305

Each test will show:
- What it's testing
- Expected vs actual behavior
- Pass/Fail result
- Supporting evidence

---

## 📁 Project Structure at a Glance

```
Assignment_one/
├── shared/                ← Shared code (used by both)
│   ├── crypto_engine.py   (AES-GCM + ChaCha20 wrapper)
│   ├── nonce_manager.py   (unique nonce generation)
│   ├── replay_detector.py (replay detection)
│   └── config.py          (constants)
│
├── server/                ← Receiver side (Person 1)
│   └── server.py          (validation & decryption)
│
├── client/                ← Sender side (Person 2)
│   ├── client.py          (encryption & record protection)
│   └── test_harness.py    (all 8 tests)
│
└── README.md              ← Full documentation
```

---

## 🧪 Testing Requirements (TR-1 to TR-8)

| # | Test | Expects |
|---|------|---------|
| **1** | Baseline | Encrypt → Decrypt successfully ✓ |
| **2** | Ciphertext | Tampered data → Rejected ✗ |
| **3** | Tag | Tampered tag → Rejected ✗ |
| **4** | AAD | Tampered metadata → Rejected ✗ |
| **5** | Replay | Duplicate record → Rejected ✗ |
| **6** | Wrong Key | Wrong key → Rejected ✗ |
| **7** | Nonces | 10,000 records → All unique ✓ |
| **8** | Performance | Speed comparison of both algorithms |

---

## 📝 Key Features Implemented

✅ **Authenticated Encryption (AEAD)**
- AES-GCM support
- ChaCha20-Poly1305 support

✅ **Nonce Management**
- Counter-based unique nonce generation
- Prevents nonce reuse (SR-3)

✅ **Replay Detection**
- Sliding window approach
- Detects duplicate and out-of-order records (SR-5)

✅ **Associated Data (AAD)**
- Optional per-record metadata
- Integrity verification (SR-4)

✅ **Strict Failure Handling**
- Never releases plaintext if authentication fails (SR-6)
- Detailed error messages

---

## 💡 For Two-Person Teams

### Person 1 — Focus on Server
```python
from server.server import ReceiverServer

# The receiver validates and decrypts
receiver = ReceiverServer(algorithm="AES-GCM", key=shared_key)
response = receiver.process_protected_record(json_record)

if response['success']:
    plaintext = response['plaintext']
else:
    print(f"Validation failed: {response['error']}")
```

### Person 2 — Focus on Client
```python
from client.client import SenderClient
from client.test_harness import TestHarness

# The sender encrypts and protects
sender = SenderClient(algorithm="AES-GCM")
protected = sender.protect_record(plaintext, aad="metadata")

# Run all tests
harness = TestHarness(algorithm="AES-GCM")
harness.run_all_tests()
```

---

## 🔍 File Overview

### `shared/crypto_engine.py` (850 lines)
- AES-GCM encryption/decryption
- ChaCha20-Poly1305 encryption/decryption
- Unified API for both algorithms

### `shared/nonce_manager.py` (130 lines)
- Generate 12-byte unique nonces
- Counter-based approach (4-byte prefix + 8-byte counter)
- Supports 2^64 unique nonces per key

### `shared/replay_detector.py` (150 lines)
- Sliding window replay detection
- Track up to 10,000 sequence numbers
- Detects both replay and out-of-order

### `client/client.py` (350 lines)
- Sender encryption logic
- Nonce management integration
- Record protection
- Tampering methods (for testing)

### `server/server.py` (250 lines)
- Receiver validation logic
- Replay detection integration
- Authentication verification
- Decryption

### `client/test_harness.py` (650 lines)
- TR-1: Positive Baseline
- TR-2: Ciphertext Integrity
- TR-3: Authentication Tag
- TR-4: Associated Data (AAD)
- TR-5: Replay Detection
- TR-6: Wrong-Key Test
- TR-7: Nonce Management (10,000 records)
- TR-8: Performance Evaluation

---

## 🎯 Expected Output Example

```
======================================================================
STARTING FULL TEST SUITE FOR AES-GCM
======================================================================

──────────────────────────────────────────────────────────────────────
TR-1: Positive Baseline Test
──────────────────────────────────────────────────────────────────────
✓ PASS Record recovered successfully

──────────────────────────────────────────────────────────────────────
TR-2: Ciphertext Integrity Test
──────────────────────────────────────────────────────────────────────
✓ PASS Tampered record correctly rejected

[... more tests ...]

======================================================================
TEST RESULTS SUMMARY FOR AES-GCM
======================================================================
TR-1: ✓ PASS
TR-2: ✓ PASS
TR-3: ✓ PASS
TR-4: ✓ PASS
TR-5: ✓ PASS
TR-6: ✓ PASS
TR-7: ✓ PASS
TR-8: ✓ PASS

Total: 8/8 tests passed (100.0%)
======================================================================
```

---

## 🛠️ Useful Commands

### Run Full Test Suite
```bash
python3 client/test_harness.py
```

### Run Tests with Output Logging
```bash
python3 client/test_harness.py 2>&1 | tee test_output.log
```

### Test Individual Requirements
```bash
python3 -c "
from client.test_harness import TestHarness

harness = TestHarness(algorithm='AES-GCM')
harness.run_tr1_positive_baseline()  # Test 1
harness.run_tr7_nonce_management()   # Test 7
harness.run_tr8_performance_evaluation()  # Test 8
"
```

### Test with ChaCha20
```bash
python3 -c "
from client.test_harness import TestHarness

harness = TestHarness(algorithm='ChaCha20-Poly1305')
harness.run_all_tests()
"
```

---

## ❓ Troubleshooting

### "ModuleNotFoundError: No module named 'cryptography'"
```bash
pip install cryptography>=41.0.0
```

### "Permission denied: ./run_tests.sh"
```bash
chmod +x run_tests.sh
./run_tests.sh
```

### Tests run but show errors
- Check that cryptography library is installed
- Verify Python 3.8+: `python3 --version`
- Check network if downloading dependencies

---

## 📚 Documentation

- **README.md** — Full project documentation
- **PROJECT_STRUCTURE.md** — Detailed component breakdown
- **SETUP.md** — This file (quick start)
- **Code comments** — Inline documentation in each module

---

## ✨ You're Ready!

```bash
# 1. Go to project directory
cd "/home/anandc2/Desktop/Crptography Assignment /Crptography/Assignment_one"

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run tests
python3 client/test_harness.py
```

**Start working! 🚀**

If you have any questions, check **README.md** or **PROJECT_STRUCTURE.md** for detailed explanations.
