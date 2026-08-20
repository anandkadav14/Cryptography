# Secure Data Protection Subsystem

**Course:** CS6530 Applied Cryptography (IIT Madras)  
**Assignment:** 1

This project is a secure data protection subsystem built with authenticated encryption (AEAD). It supports **AES-GCM** and **ChaCha20-Poly1305**.

It covers:
- Shared-key encryption and decryption
- Nonce management (unique nonces under one key)
- Associated authenticated data (AAD)
- Replay detection

---

## 📋 Quick Navigation

1. **[Setup](#1-setup)** — Before running anything
2. **[Automated Tests](#2-automated-tests)** — Run all tests at once
3. **[Manual Tests](#3-manual-tests)** — Interactive testing
4. **[Project Structure](#4-project-structure)** — File overview

---

## 1. Setup

### 1.1 System Requirements

| Item | Details |
|------|---------|
| **OS** | Windows, Linux, or macOS |
| **Python** | 3.10 or newer (3.11+ preferred) |
| **Package Manager** | `pip` (included with Python) |

### 1.2 Install Python Dependencies

Navigate to the `Assignment_one` folder and create a virtual environment:

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 1.3 Verify Installation

```bash
python3 -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305; print('✓ Setup complete')"
```

You should see: `✓ Setup complete`

---

## 2. Automated Tests

### 2.1 What Automated Tests Do

The automated test suite runs **all 8 testing requirements (TR-1 to TR-8)** plus an extra sequence-binding check for **both algorithms** (AES-GCM and ChaCha20-Poly1305).

**What you'll see:**
- ✅ Each test shows the SYSTEM FLOW (what's being called inside)
- ✅ Evidence for why each test PASSED
- ✅ Performance metrics
- ✅ Full results saved to `evidence/` folder

### 2.2 Run Automated Tests

Make sure virtual environment is activated, then:

```bash
python3 run_tests.py
```

**Or on Linux/macOS:**
```bash
bash run_tests.sh
```

### 2.3 Example Automated Test Output

```
======================================================================
CS6530 Assignment 1 — Automated TR-1..TR-8 Harness
======================================================================

=== AES-GCM ===

  Running TR-1 ...
    Status: PASS
    Title: Positive Baseline Test
    Evidence:
      [SENDER] Input plaintext: 'Hello Alice', AAD: 'msg-type:chat'
      [SENDER] → Calling protect_record()
        ✓ Generated nonce: f79956b400000000d2adcadc
        ✓ Encrypted (ciphertext size: 11 bytes)
        ✓ Generated auth tag: 5b63aade6d4cace2...
        ✓ AAD in AEAD: seq=0|msg-type:chat
      [NETWORK] Transmitting protected record as JSON
      [RECEIVER] → Calling process_protected_record()
        ✓ Parsed JSON
        ✓ Checked replay → OK (new sequence)
        ✓ Verified authentication tag → OK
        ✓ Decrypted ciphertext
        ✓ Recovered plaintext: 'Hello Alice'
      [VERIFICATION] Match original: True ✓
    ✓ PASS

  Running TR-2 ...
    Status: PASS
    Title: Ciphertext Integrity Test
    Evidence:
      [SENDER] Encrypting plaintext: 'integrity-plaintext'
        ✓ Ciphertext: e517e7cc342e6783...
        ✓ Auth tag: 68d4e885ff8979e5...
      [MALICIOUS ACTOR] Tampering with ciphertext...
        Original:  e517e7cc342e6783... (byte 1 = 0xE5)
        Tampered:  1a17e7cc342e6783... (byte 1 = 0x1A - FLIPPED!)
      [RECEIVER] Processing tampered record...
        ✗ COMPUTED TAG DOESN'T MATCH
        ✗ Authentication FAILED
        ✗ Plaintext NOT released
    ✓ PASS

  ... (TR-3 through TR-8)
```

### 2.4 Test Results

After tests complete, results are saved in:

```
evidence/
├── AES-GCM/
│   ├── TR-1.txt through TR-8.txt     (detailed results for each test)
│   ├── EXTRA-SEQ-BIND.txt            (sequence binding test)
│   └── summary.json                  (structured data)
├── ChaCha20-Poly1305/
│   ├── TR-1.txt through TR-8.txt
│   ├── EXTRA-SEQ-BIND.txt
│   └── summary.json
└── summary/
    ├── TEST_SUMMARY.md               (human-readable summary)
    └── TEST_SUMMARY.json             (machine-readable summary)
```

### 2.5 View Results

**Summary table:**
```bash
cat evidence/summary/TEST_SUMMARY.md
```

**Detailed result for specific test:**
```bash
cat evidence/AES-GCM/TR-7.txt
```

### 2.6 Testing Requirements Covered (Automated)

| Test | Name | What It Tests |
|------|------|---------------|
| **TR-1** | Positive Baseline | Encrypt → Decrypt → Verify plaintext matches |
| **TR-2** | Ciphertext Integrity | Tamper ciphertext → Should be rejected |
| **TR-3** | Authentication Tag | Tamper tag → Should be rejected |
| **TR-4** | Associated Data (AAD) | Tamper AAD → Should be rejected |
| **TR-5** | Replay Detection | Send same record twice → 2nd rejected |
| **TR-6** | Wrong Key | Decrypt with wrong key → Should fail |
| **TR-7** | Nonce Uniqueness | Generate 10,000 nonces → All unique |
| **TR-8** | Performance | Measure encrypt/decrypt time |
| **EXTRA** | Sequence Binding | Sequence tampering → Should be rejected |

---

## 3. Manual Tests

### 3.1 What Manual Tests Do

The interactive CLI (`main.py`) lets you:
- ✅ Manually encrypt plaintext with optional AAD
- ✅ Manually decrypt protected records
- ✅ Tamper with records and see detection
- ✅ Test individual algorithms
- ✅ See real-time system behavior

### 3.2 Run Manual Tests

Make sure virtual environment is activated, then:

```bash
python3 main.py
```

### 3.3 Interactive Menu

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

### 3.4 Manual Testing Workflow

#### Step 1: Select Algorithm
```
Enter choice (1-9): 1
Choose AEAD Algorithm:
  1. AES-GCM
  2. ChaCha20-Poly1305
Enter choice (1 or 2): 1
✓ Selected: AES-GCM
✓ Shared Key: 3b187974f5890205a1276aa84d1ff922...
```

#### Step 2: Encrypt Record (Sender)
```
Enter choice (1-9): 2
Enter plaintext to encrypt: hello world
Enter Associated Data (AAD) [optional, press Enter to skip]: test-metadata

✓ Record encrypted successfully!
Protected Record Details:
  Sequence:    0
  Nonce:       51ee63f300000000ab4ee1ff
  Ciphertext:  013c2090913ee25176e02f
  Tag:         51b7f80e20301ebee64cbc579f6d7c3f
  AAD:         7365713d307c746573742d6d65746164617461
  Algorithm:   AES-GCM

Full Protected Record (JSON):
{
  "sequence": 0,
  "nonce": "51ee63f300000000ab4ee1ff",
  "ciphertext": "013c2090913ee25176e02f",
  "tag": "51b7f80e20301ebee64cbc579f6d7c3f",
  "aad": "7365713d307c746573742d6d65746164617461",
  "algorithm": "AES-GCM",
  "plaintext_length": 11
}
```

#### Step 3: Decrypt Record (Receiver)
```
Enter choice (1-9): 3
Use last encrypted record? (y/n): y

✓ Record decrypted successfully!
Decrypted Details:
  Plaintext: hello world
  Sequence:  0
  Algorithm: AES-GCM
  AAD valid: ✓
✓ Plaintext matches original!
```

#### Step 4: Tamper & Test Detection
```
Enter choice (1-9): 4
Tamper options:
  1. Tamper ciphertext
  2. Tamper authentication tag
  3. Tamper AAD
  4. Replay (send same record twice)
Enter choice (1-4): 1

→ Tampering with ciphertext...
✓ Ciphertext tampered!
  Original:  d59028b3e08b3824101c2c...
  Tampered:  2a9028b3e08b3824101c2c...

→ Attempting to decrypt tampered record...
✓ DETECTED! Record rejected: Authentication verification failed
```

### 3.5 Advanced Manual Tests

**Test 5: Wrong Key (TR-6)**
```
Enter choice (1-9): 5
Key Testing Options:
  1. Test with CORRECT key (should succeed)
  2. Test with WRONG key (auto-generated)
  3. Test with CUSTOM key (paste your own hex key)
```

**Test 6: Nonce Uniqueness (TR-7)**
```
Enter choice (1-9): 6
How many records to test? (default 10000): 100
Generating 100 records and checking for nonce uniqueness...
✓ PASSED! Generated 100 records with all unique nonces
```

**Test 7: Performance (TR-8)**
```
Enter choice (1-9): 7
Size    Encrypt(ms)  Decrypt(ms)  Total(ms)  Throughput(MB/s)
64B         0.147        0.061      0.207        0.29
1KiB        0.039        0.044      0.083       11.74
64KiB       0.174        0.224      0.397      157.25
```

**Test 8: View Shared Key**
```
Enter choice (1-9): 8
Shared Key (hex format - 64 characters):
3b187974f5890205a1276aa84d1ff92287fb2e9b1a15fba9251cb5b38a9cdbc46

Use this key for TR-6 custom key testing (paste the full 64-char hex string)
```

---

## 4. Project Structure

```
Cryptography/
├── README.md                 # This file
├── .gitignore                # Git ignore rules
└── Assignment_one/
    ├── README.md             # Full guide (this file)
    ├── main.py               # ⭐ Interactive CLI for manual testing
    ├── run_tests.py          # ⭐ Automated test suite (TR-1 to TR-8)
    ├── run_tests.sh          # Helper script (Linux/macOS)
    ├── requirements.txt      # Python dependencies
    │
    ├── client/               # 👤 SENDER SIDE
    │   ├── __init__.py
    │   └── client.py         # SenderClient class (encrypts records)
    │
    ├── server/               # 👤 RECEIVER SIDE
    │   ├── __init__.py
    │   └── server.py         # ReceiverServer class (validates & decrypts)
    │
    ├── shared/               # ⭐ SHARED CODE (both use)
    │   ├── __init__.py
    │   ├── config.py         # Constants (key size, nonce size, etc.)
    │   ├── crypto_engine.py  # AEAD wrapper (AES-GCM + ChaCha20)
    │   ├── nonce_manager.py  # Unique nonce generation
    │   ├── replay_detector.py # Replay detection (sliding window)
    │   └── aad_utils.py      # Sequence binding to AAD
    │
    ├── evidence/             # 📊 Test results (auto-generated)
    │   ├── AES-GCM/
    │   ├── ChaCha20-Poly1305/
    │   └── summary/
    │
    └── docs/                 # 📝 Your report draft
```

### Component Responsibilities

| File | Responsibility |
|------|----------------|
| `crypto_engine.py` | Encrypt/decrypt with AES-GCM or ChaCha20-Poly1305 |
| `nonce_manager.py` | Generate unique 12-byte nonces (no reuse) |
| `replay_detector.py` | Track sequence numbers, detect replays |
| `aad_utils.py` | Bind sequence number into AAD (new security feature) |
| `client.py` | Sender: encrypt plaintext, manage nonce, create protected record |
| `server.py` | Receiver: validate replay, verify tag, decrypt |
| `main.py` | Interactive menu for manual testing |
| `run_tests.py` | Automated test harness (all 8 requirements) |

---

## 5. Key Features

### Nonce Management
- ✅ **Format**: 4-byte random prefix + 8-byte incremental counter
- ✅ **Uniqueness**: 2^64 unique nonces per key (no collisions)
- ✅ **Behavior**: Randomized start per session, incremental within session

### Replay Detection
- ✅ **Method**: Sliding window with sequence numbers
- ✅ **Window**: Tracks up to 10,000 sequences
- ✅ **Detection**: Catches duplicates and out-of-order records

### Associated Data (AAD)
- ✅ **Format**: `seq=<sequence>|<user-metadata>`
- ✅ **Protection**: Included in AEAD authentication tag
- ✅ **Security**: Tampering with sequence causes tag verification to fail

### Supported Algorithms
| Algorithm | Key Size | Nonce Size | Tag Size |
|-----------|----------|-----------|----------|
| **AES-GCM** | 256 bits | 96 bits | 128 bits |
| **ChaCha20-Poly1305** | 256 bits | 96 bits | 128 bits |

---

## 6. Troubleshooting

### "ModuleNotFoundError: No module named 'cryptography'"
```bash
pip install cryptography>=41.0.0
```

### Virtual environment not activating
**Windows:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\venv\Scripts\Activate.ps1
```

**Linux/macOS:**
```bash
source venv/bin/activate
```

### Tests not running
Make sure you're in the `Assignment_one` directory and virtual environment is activated:
```bash
which python3  # Should show path inside venv/
python3 run_tests.py
```

---

## 7. Testing Summary

### Automated Tests (run_tests.py)
- ✅ Runs all tests unattended
- ✅ Shows system flow and evidence
- ✅ Saves results to `evidence/` folder
- ✅ Takes ~5-10 seconds

### Manual Tests (main.py)
- ✅ Interactive menu-driven
- ✅ See results in real-time
- ✅ Test individual algorithms
- ✅ Manual tampering experiments

### Combined Approach
1. Run automated tests for comprehensive validation
2. Run manual tests for interactive exploration
3. Capture both for your report

---

## 8. Next Steps

1. **Complete Setup** (5 min):
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Run Automated Tests** (5 min):
   ```bash
   python3 run_tests.py
   ```

3. **Run Manual Tests** (10 min):
   ```bash
   python3 main.py
   ```

4. **Review Results**:
   ```bash
   cat evidence/summary/TEST_SUMMARY.md
   ```

5. **Write Report**:
   - Document design decisions
   - Include test evidence
   - Compare algorithm performance
   - Discuss security implications

---

## ✅ Verification Checklist

- [ ] Setup complete (venv activated, requirements installed)
- [ ] Automated tests pass (all 18 tests: 9 per algorithm)
- [ ] Manual tests work (can encrypt/decrypt)
- [ ] Both algorithms tested
- [ ] Evidence folder populated
- [ ] Report written with screenshots

---

**You're all set! Start with:** `python3 run_tests.py` 🚀
