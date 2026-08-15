# Project Structure & Setup Summary

## ✅ Project Created Successfully

Your secure data protection subsystem has been fully scaffolded with server/client/shared architecture.

---

## 📁 Directory Structure

```
Assignment_one/
│
├── shared/                          ⭐ SHARED CODE (Both use)
│   ├── __init__.py
│   ├── config.py                    Configuration constants
│   ├── crypto_engine.py             AES-GCM + ChaCha20-Poly1305 wrapper
│   ├── nonce_manager.py             Counter-based unique nonce generation
│   └── replay_detector.py           Sliding window replay detection
│
├── server/                          👤 RECEIVER SIDE (Person 1)
│   ├── __init__.py
│   └── server.py                    ReceiverServer class
│       - Listens for protected records
│       - Verifies authentication (TR-2, TR-3, TR-4)
│       - Detects replays (TR-5)
│       - Decrypts records
│       - Returns validation results
│
├── client/                          👤 SENDER SIDE (Person 2)
│   ├── __init__.py
│   ├── client.py                    SenderClient class
│   │   - Encrypts plaintext records
│   │   - Manages nonce generation
│   │   - Creates protected records
│   │   - Can tamper with records (for testing)
│   │
│   └── test_harness.py              🧪 TEST SUITE (TR-1 to TR-8)
│       - TR-1: Positive Baseline Test
│       - TR-2: Ciphertext Integrity Test
│       - TR-3: Authentication Tag Test
│       - TR-4: Associated Data (AAD) Test
│       - TR-5: Replay Test
│       - TR-6: Wrong-Key Test
│       - TR-7: Nonce Management Verification (10,000 records)
│       - TR-8: Performance Evaluation
│
├── requirements.txt                 Python dependencies
├── README.md                        Full documentation
├── run_tests.sh                     Test execution script
└── PROJECT_STRUCTURE.md            This file
```

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd "/home/anandc2/Desktop/Crptography Assignment /Crptography/Assignment_one"
pip install -r requirements.txt
```

### 2. Run All Tests (Both Algorithms)

```bash
python3 client/test_harness.py
```

Or use the shell script:

```bash
./run_tests.sh
```

---

## 🛠️ Component Breakdown

### Shared Code (`shared/`)

#### 1. **config.py** — Configuration Constants
- Algorithm types: `ALGORITHM_AES_GCM`, `ALGORITHM_CHACHA20`
- Nonce size: 12 bytes (96 bits)
- Tag size: 16 bytes (128 bits)
- Key size: 32 bytes (256 bits)
- Test sizes: 64B, 1KB, 64KB (for TR-8)
- Nonce test count: 10,000 (for TR-7)

#### 2. **crypto_engine.py** — AEAD Encryption/Decryption
```python
engine = CryptoEngine(algorithm="AES-GCM", key=key_bytes)

# Encrypt
result = engine.encrypt(plaintext, nonce, aad)
# Returns: {ciphertext, tag, algorithm}

# Decrypt & Verify
plaintext = engine.decrypt(ciphertext, tag, nonce, aad)
# Raises AuthenticationError if verification fails
```

**Features:**
- Supports both AES-GCM and ChaCha20-Poly1305
- Automatic tag extraction (last 16 bytes)
- AAD support (optional)
- Hex key import/export

#### 3. **nonce_manager.py** — Nonce Generation
```python
manager = NonceManager()
nonce = manager.generate_nonce()  # 12-byte unique nonce
```

**Nonce Strategy:**
- Counter-based: 4-byte prefix + 8-byte counter
- Guarantees uniqueness: 2^64 unique nonces per key
- Tracks all generated nonces
- Prevents nonce reuse (SR-3)

#### 4. **replay_detector.py** — Replay Detection
```python
detector = ReplayDetector()
result = detector.check_and_update(sequence_number)
# Returns: {is_replay, is_out_of_order, message}
```

**Features:**
- Sliding window approach
- Window size: 10,000 (configurable)
- Tracks sequence numbers
- Detects duplicate and out-of-order records

---

### Server Code (`server/server.py`)

#### ReceiverServer Class

**Responsibility:** Validate and decrypt incoming protected records

**Key Methods:**
```python
server = ReceiverServer(algorithm="AES-GCM", key=key_hex)

# Process protected record
response = server.process_protected_record(json_record_string)

# Response format:
# {
#   'success': bool,
#   'plaintext': str (if successful),
#   'error': str (if failed),
#   'replay': bool,
#   'sequence': int,
#   'algorithm': str
# }
```

**Processing Pipeline:**
1. Parse JSON record
2. ✅ Replay verification (SR-5)
3. ✅ Authentication verification (SR-2, SR-6)
4. ✅ Decryption (SR-1)
5. ✅ Return plaintext (or error)

**Security Features:**
- Strict failure handling (never releases partial plaintext)
- Detailed error messages
- Operation logging
- Statistics tracking

---

### Client Code (`client/client.py`)

#### SenderClient Class

**Responsibility:** Encrypt and prepare protected records for transmission

**Key Methods:**
```python
client = SenderClient(algorithm="AES-GCM", key=key_bytes)

# Protect a record
protected = client.protect_record(plaintext, aad="metadata")

# Send record (JSON serialization)
json_str = client.send_record(protected)

# Create tampered versions (for testing)
tampered_ciphertext = client.create_tampered_ciphertext(protected)
tampered_tag = client.create_tampered_tag(protected)
tampered_aad = client.create_tampered_aad(protected)
```

**Features:**
- Automatic nonce generation (unique per record)
- AAD binding (optional metadata)
- Ciphertext/tag/AAD tampering (for negative tests)
- Statistics and logging

---

### Test Harness (`client/test_harness.py`)

#### TestHarness Class

**Runs all 8 testing requirements:**

```python
harness = TestHarness(algorithm="AES-GCM")

# Run individual tests
harness.run_tr1_positive_baseline()      # ✓ Normal flow
harness.run_tr2_ciphertext_integrity()   # ✗ Tampered ciphertext
harness.run_tr3_authentication_tag_test()# ✗ Tampered tag
harness.run_tr4_aad_test()               # ✗ Tampered AAD
harness.run_tr5_replay_test()            # ✗ Replayed record
harness.run_tr6_wrong_key_test()         # ✗ Wrong key
harness.run_tr7_nonce_management()       # 10,000 unique nonces
harness.run_tr8_performance_evaluation() # Performance metrics

# Run all tests
results = harness.run_all_tests()
```

**Output:**
- Color-coded pass/fail indicators
- Detailed operation logs
- Performance measurements
- Summary statistics

---

## 📋 Testing Requirements Mapping

| TR | Test Name | Purpose | Method |
|----|-----------|---------|--------|
| **TR-1** | Positive Baseline | Normal flow | Encrypt → Send → Verify → Decrypt |
| **TR-2** | Ciphertext Integrity | Authentication | Tamper ciphertext → should fail |
| **TR-3** | Authentication Tag | Authentication | Tamper tag → should fail |
| **TR-4** | AAD Protection | AAD integrity | Tamper AAD → should fail |
| **TR-5** | Replay Detection | Replay protection | Send same record twice → 2nd fails |
| **TR-6** | Wrong-Key Test | Key verification | Decrypt with wrong key → should fail |
| **TR-7** | Nonce Management | Nonce uniqueness | Process 10,000 records → all unique |
| **TR-8** | Performance | Speed comparison | Measure both algorithms |

---

## 🔑 Key Design Decisions

### 1. Nonce Management (FR-5, SR-3)
**Strategy:** Counter-based (prefix + counter)
**Why:** 
- Guarantees uniqueness without random collision risk
- Suitable for long-lived keys
- Scales to 2^64 unique nonces per key

### 2. Replay Detection (FR-8, SR-5)
**Strategy:** Sliding window with sequence numbers
**Why:**
- Efficient memory usage (10,000-record window)
- Detects both replay and reordering attacks
- Deterministic (no probabilistic failures)

### 3. Associated Data (FR-4, SR-4)
**Usage:** Optional per-record metadata
**Examples:**
- `"user:alice"` — bind to user
- `"timestamp:2026-08-15"` — bind to time
- `"sequence:1234"` — bind to order

### 4. Record Format
**JSON-based for clarity:**
```json
{
  "sequence": 0,
  "nonce": "hex_string",
  "ciphertext": "hex_string",
  "tag": "hex_string",
  "aad": "hex_string",
  "algorithm": "AES-GCM"
}
```

---

## 👥 Two-Person Collaboration Guide

### Person 1 — Server/Receiver Side
**Focus:** Validation and decryption

**Tasks:**
1. Study `server/server.py` (ReceiverServer class)
2. Understand replay detection logic
3. Run TR-1, TR-5, TR-7 to validate receiver side
4. Test authentication failure handling (TR-2, TR-3, TR-4, TR-6)

**Key Files:**
- `server/server.py`
- `shared/replay_detector.py`
- `shared/crypto_engine.py`

### Person 2 — Client/Sender Side
**Focus:** Encryption and test harness

**Tasks:**
1. Study `client/client.py` (SenderClient class)
2. Understand record protection flow
3. Study tampering methods (for negative tests)
4. Run complete test harness (TR-1 to TR-8)

**Key Files:**
- `client/client.py`
- `client/test_harness.py`
- `shared/nonce_manager.py`
- `shared/crypto_engine.py`

### Shared Understanding
**Both should know:**
- How crypto_engine.py works
- Nonce generation and uniqueness requirements
- Record format (JSON structure)
- Test expectations (what should pass/fail)

---

## 📊 Expected Test Output

```
======================================================================
STARTING FULL TEST SUITE FOR AES-GCM
======================================================================

──────────────────────────────────────────────────────────────────────
TR-1: Positive Baseline Test
Description: Valid record protection, transmission, and recovery
──────────────────────────────────────────────────────────────────────

1. Sender protecting record...
   Plaintext: Hello, World! This is a test message.
   AAD: metadata:test
   [CLIENT] INFO: [Seq 0] Generated nonce: a1b2c3d4e5f6a1b2...

2. Receiver processing record...
   [SERVER] INFO: [Sequence 0] Checking for replay...
   [SERVER] INFO: [Sequence 0] Verifying authentication...
   [SERVER] INFO: [Sequence 0] ✓ Authentication verified
   Decrypted plaintext: Hello, World! This is a test message.

✓ PASS Record recovered successfully


── TR-2: Ciphertext Integrity Test ──
✓ PASS Tampered record correctly rejected

── TR-3: Authentication Tag Test ──
✓ PASS Modified tag correctly detected

── TR-4: Associated Data (AAD) Test ──
✓ PASS AAD tampering correctly detected

── TR-5: Replay Test ──
✓ PASS Replay correctly detected and rejected

── TR-6: Wrong-Key Test ──
✓ PASS Wrong key correctly caused authentication failure

── TR-7: Nonce Management Verification ──
Processed 10000 records, no reuse detected
✓ PASS All nonces unique - no reuse detected

── TR-8: Performance Evaluation ──
--- Testing 64 bytes (0.1 KB) ---
  Encryption: 0.234 ms
  Decryption: 0.156 ms
  Total:      0.390 ms
  Throughput: 164.10 MB/s

--- Testing 1024 bytes (1.0 KB) ---
  Encryption: 0.289 ms
  Decryption: 0.201 ms
  Total:      0.490 ms
  Throughput: 2088.36 MB/s

--- Testing 65536 bytes (64.0 KB) ---
  Encryption: 11.450 ms
  Decryption: 8.230 ms
  Total:      19.680 ms
  Throughput: 3325.85 MB/s

✓ PASS Performance evaluation complete

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

## 📝 Next Steps

1. ✅ **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. ✅ **Run tests to verify setup:**
   ```bash
   python3 client/test_harness.py
   ```

3. 📝 **Review the code:**
   - Start with `shared/config.py` (constants)
   - Then `shared/crypto_engine.py` (encryption/decryption)
   - Then `client/client.py` (sender logic)
   - Then `server/server.py` (receiver logic)
   - Finally `client/test_harness.py` (all tests)

4. 💾 **Capture test output for your report:**
   ```bash
   python3 client/test_harness.py 2>&1 | tee test_results_aes_gcm.log
   ```

5. 📊 **Performance analysis (TR-8):**
   - Compare AES-GCM vs ChaCha20-Poly1305
   - Create comparison charts
   - Include in report

---

## 🎯 Deliverables

### D1 — Source Code
✅ Ready: Complete source code in `shared/`, `server/`, `client/`

### D2 — Assignment 1 Report
📋 To do:
- Design Summary (architecture, decisions)
- Testing Results (TR-1 to TR-8, with evidence)
- Performance Analysis (compare both algorithms)
- Discussion (observations, lessons learned)

### D3 — README
✅ Ready: Detailed README.md with all instructions

---

## ⚠️ Important Reminders

1. **Both algorithms must be tested separately:**
   - Run full suite with `ALGORITHM_AES_GCM`
   - Run full suite with `ALGORITHM_CHACHA20`
   - Report results for both

2. **Nonce uniqueness (TR-7):**
   - Test with ~10,000 records
   - Verify no nonce repeats
   - Document strategy used

3. **Performance (TR-8):**
   - Test both algorithms
   - Measure 64B, 1KB, 64KB records
   - Compare throughput and latency

4. **Security:**
   - Never release plaintext on auth failure (SR-6)
   - Always verify tags before decryption
   - Detect replays before decryption

---

## 🔗 File Dependencies

```
test_harness.py
├── imports: SenderClient (client.py)
├── imports: ReceiverServer (server.py)
└── uses: CryptoEngine, NonceManager, ReplayDetector (shared/)

client.py
├── imports: CryptoEngine, NonceManager (shared/)
└── uses: config (shared/config.py)

server.py
├── imports: CryptoEngine, ReplayDetector (shared/)
└── uses: config (shared/config.py)

shared/crypto_engine.py
├── uses: AESGCM, ChaCha20Poly1305 (cryptography library)
└── uses: config (shared/config.py)
```

---

## ✨ You're All Set!

Your project is ready to run. Execute the test suite and start developing!

```bash
python3 client/test_harness.py
```

**Good luck with your assignment! 🚀**
