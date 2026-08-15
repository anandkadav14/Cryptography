# Manual Setup & Testing Guide

Complete step-by-step instructions to set up and test the secure data protection subsystem.

---

## Part 1: Initial Setup

### Step 1.1: Navigate to Project Directory

```bash
cd "/home/anandc2/Desktop/Crptography Assignment /Crptography/Assignment_one"
```

Verify you're in the right location:
```bash
pwd
# Should output: /home/anandc2/Desktop/Crptography Assignment /Crptography/Assignment_one

ls -la
# Should show: client  server  shared  README.md  requirements.txt  venv/
```

---

### Step 1.2: Activate Virtual Environment

The virtual environment is already created. Just activate it:

```bash
source venv/bin/activate
```

You should see `(venv)` in your terminal prompt:
```bash
(venv) anandc2@c2-HP-Z2:~/Desktop/Crptography Assignment /Crptography/Assignment_one$
```

---

### Step 1.3: Verify Dependencies are Installed

```bash
pip list | grep cryptography
# Should show: cryptography 50.0.0
```

Or verify imports work:
```bash
python3 -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305; print('✓ Cryptography library OK')"
# Output: ✓ Cryptography library OK
```

---

## Part 2: Running the Full Test Suite

### Step 2.1: Run All Tests (Both Algorithms)

```bash
python3 client/test_harness.py
```

This runs:
- ✅ AES-GCM: All 8 tests (TR-1 to TR-8)
- ✅ ChaCha20-Poly1305: All 8 tests (TR-1 to TR-8)

**Expected Duration:** ~2-3 minutes

**Expected Output:** Ends with:
```
======================================================================
FINAL SUMMARY - BOTH ALGORITHMS
======================================================================

AES-GCM: 8/8 tests passed

ChaCha20-Poly1305: 8/8 tests passed
```

---

### Step 2.2: Save Test Output to File (For Your Report)

```bash
python3 client/test_harness.py 2>&1 | tee test_results_$(date +%Y%m%d_%H%M%S).log
```

This creates a file like: `test_results_20260815_140000.log`

View the results:
```bash
tail -50 test_results_*.log
```

---

## Part 3: Individual Test Execution

Run specific tests manually instead of the full suite:

### Option A: Test Individual Requirement (Single Algorithm)

```bash
python3 << 'EOF'
from client.test_harness import TestHarness

# Test AES-GCM only
harness = TestHarness(algorithm='AES-GCM')

# Run individual tests
harness.run_tr1_positive_baseline()      # Normal operation
harness.run_tr2_ciphertext_integrity()   # Tampered data
harness.run_tr3_authentication_tag_test()# Tampered tag
harness.run_tr4_aad_test()               # Tampered AAD
harness.run_tr5_replay_test()            # Replay detection
harness.run_tr6_wrong_key_test()         # Wrong key
harness.run_tr7_nonce_management()       # 10,000 nonces
harness.run_tr8_performance_evaluation() # Performance
EOF
```

### Option B: Test One Algorithm Only

```bash
python3 << 'EOF'
from client.test_harness import TestHarness

# Test only AES-GCM (not ChaCha20)
harness = TestHarness(algorithm='AES-GCM')
results = harness.run_all_tests()
EOF
```

Or test only ChaCha20:

```bash
python3 << 'EOF'
from client.test_harness import TestHarness

# Test only ChaCha20-Poly1305 (not AES-GCM)
harness = TestHarness(algorithm='ChaCha20-Poly1305')
results = harness.run_all_tests()
EOF
```

---

## Part 4: Component Testing (Advanced)

Test individual components in isolation:

### 4.1: Test Crypto Engine

```bash
python3 << 'EOF'
from shared.crypto_engine import CryptoEngine, AuthenticationError
import os

# Create engine with AES-GCM
engine = CryptoEngine(algorithm="AES-GCM")
print(f"✓ Created crypto engine with AES-GCM")

# Generate test data
plaintext = b"Hello, World!"
nonce = os.urandom(12)
aad = b"metadata"

# Encrypt
result = engine.encrypt(plaintext, nonce, aad)
print(f"✓ Encrypted: {len(result['ciphertext'])} bytes of ciphertext")
print(f"  Tag: {result['tag'].hex()}")

# Decrypt
recovered = engine.decrypt(result['ciphertext'], result['tag'], nonce, aad)
print(f"✓ Decrypted: {recovered}")
print(f"  Match: {recovered == plaintext}")

# Try with wrong AAD (should fail)
try:
    wrong_aad = b"wrong_metadata"
    engine.decrypt(result['ciphertext'], result['tag'], nonce, wrong_aad)
    print("✗ ERROR: Should have failed with wrong AAD!")
except AuthenticationError:
    print("✓ Correctly rejected wrong AAD")
EOF
```

---

### 4.2: Test Nonce Manager

```bash
python3 << 'EOF'
from shared.nonce_manager import NonceManager

manager = NonceManager()

# Generate 100 nonces
print("Generating 100 nonces...")
nonces = set()
for i in range(100):
    nonce = manager.generate_nonce()
    nonces.add(nonce.hex())
    if (i + 1) % 20 == 0:
        print(f"  Generated {i + 1} nonces")

print(f"✓ Total unique nonces: {len(nonces)}")
print(f"✓ Expected: 100")
print(f"✓ Nonce manager working correctly: {len(nonces) == 100}")

# Check state
state = manager.export_state()
print(f"✓ State: {state}")
EOF
```

---

### 4.3: Test Replay Detector

```bash
python3 << 'EOF'
from shared.replay_detector import ReplayDetector

detector = ReplayDetector()

print("Testing replay detection...")

# Sequence 1: First time - should pass
result1 = detector.check_and_update(1)
print(f"Sequence 1 (first): {result1['message']}")
assert not result1['is_replay'], "Should not be detected as replay"

# Sequence 2: New sequence - should pass
result2 = detector.check_and_update(2)
print(f"Sequence 2 (new): {result2['message']}")
assert not result2['is_replay'], "Should not be detected as replay"

# Sequence 1: Replay attempt - should fail
result3 = detector.check_and_update(1)
print(f"Sequence 1 (replay): {result3['message']}")
assert result3['is_replay'], "Should be detected as replay"

# Sequence 0: Out of order - should fail
result4 = detector.check_and_update(0)
print(f"Sequence 0 (out-of-order): {result4['message']}")
assert result4['is_replay'], "Should be detected as replay"

print("✓ All replay detection tests passed")
EOF
```

---

### 4.4: Test Sender Client

```bash
python3 << 'EOF'
from client.client import SenderClient
from shared.config import ALGORITHM_AES_GCM

client = SenderClient(algorithm=ALGORITHM_AES_GCM)

# Create a record
plaintext = "This is a test message"
aad = "user:alice"

print("Testing SenderClient...")
protected = client.protect_record(plaintext, aad)

print(f"✓ Protected record created")
print(f"  Sequence: {protected['sequence']}")
print(f"  Nonce: {protected['nonce'][:16]}...")
print(f"  Ciphertext size: {len(protected['ciphertext']) // 2} bytes")
print(f"  Tag: {protected['tag'][:16]}...")
print(f"  Algorithm: {protected['algorithm']}")

# Get statistics
stats = client.get_statistics()
print(f"✓ Statistics: {stats}")
EOF
```

---

### 4.5: Test Receiver Server

```bash
python3 << 'EOF'
from server.server import ReceiverServer
from client.client import SenderClient
from shared.config import ALGORITHM_AES_GCM
import json

# Create sender and receiver with shared key
sender = SenderClient(algorithm=ALGORITHM_AES_GCM)
key_hex = sender.get_shared_key_hex()
key_bytes = bytes.fromhex(key_hex)
receiver = ReceiverServer(algorithm=ALGORITHM_AES_GCM, key=key_bytes)

print("Testing Sender → Receiver flow...")

# Sender creates record
plaintext = "Secret message"
aad = "metadata"
protected = sender.protect_record(plaintext, aad)
json_record = sender.send_record(protected)

print(f"✓ Sender created protected record")

# Receiver processes record
response = receiver.process_protected_record(json_record)

print(f"✓ Receiver processed record")
print(f"  Success: {response['success']}")
print(f"  Plaintext: {response['plaintext']}")
print(f"  Match: {response['plaintext'] == plaintext}")

# Get statistics
stats = receiver.get_statistics()
print(f"✓ Receiver statistics: {stats}")
EOF
```

---

## Part 5: Performance Testing (TR-8)

### 5.1: Test Single Size

```bash
python3 << 'EOF'
from client.test_harness import TestHarness
from shared.config import ALGORITHM_AES_GCM
import time

# Create harness
harness = TestHarness(algorithm=ALGORITHM_AES_GCM)

# Test encryption/decryption of 1 KB
record_size = 1024
plaintext = "X" * record_size
aad = "metadata"

print(f"Testing {record_size} byte record...")

# Time encryption
start = time.time()
protected = harness.sender.protect_record(plaintext, aad)
encrypt_time = (time.time() - start) * 1000

# Time decryption
json_record = harness.sender.send_record(protected)
start = time.time()
response = harness.receiver.process_protected_record(json_record)
decrypt_time = (time.time() - start) * 1000

total_time = encrypt_time + decrypt_time
throughput = (record_size / (total_time / 1000)) / 1024 / 1024  # MB/s

print(f"✓ Encryption: {encrypt_time:.3f} ms")
print(f"✓ Decryption: {decrypt_time:.3f} ms")
print(f"✓ Total:      {total_time:.3f} ms")
print(f"✓ Throughput: {throughput:.2f} MB/s")
EOF
```

---

### 5.2: Compare Both Algorithms

```bash
python3 << 'EOF'
from client.test_harness import TestHarness
from shared.config import ALGORITHM_AES_GCM, ALGORITHM_CHACHA20
import time

def test_algorithm(algorithm, record_size):
    harness = TestHarness(algorithm=algorithm)
    plaintext = "X" * record_size
    aad = "metadata"
    
    # Encryption
    start = time.time()
    protected = harness.sender.protect_record(plaintext, aad)
    encrypt_ms = (time.time() - start) * 1000
    
    # Decryption
    json_record = harness.sender.send_record(protected)
    start = time.time()
    response = harness.receiver.process_protected_record(json_record)
    decrypt_ms = (time.time() - start) * 1000
    
    total_ms = encrypt_ms + decrypt_ms
    throughput = (record_size / (total_ms / 1000)) / 1024 / 1024
    
    return encrypt_ms, decrypt_ms, total_ms, throughput

print("Comparing AES-GCM vs ChaCha20-Poly1305")
print("=" * 60)

for size in [64, 1024, 65536]:
    print(f"\n{size} bytes:")
    
    # AES-GCM
    enc, dec, total, tput = test_algorithm(ALGORITHM_AES_GCM, size)
    print(f"  AES-GCM:      {total:.3f} ms ({tput:.2f} MB/s)")
    
    # ChaCha20
    enc, dec, total, tput = test_algorithm(ALGORITHM_CHACHA20, size)
    print(f"  ChaCha20:     {total:.3f} ms ({tput:.2f} MB/s)")
EOF
```

---

## Part 6: Testing Edge Cases

### 6.1: Test Nonce Reuse Prevention

```bash
python3 << 'EOF'
from client.client import SenderClient
from shared.config import ALGORITHM_AES_GCM
import os

client = SenderClient(algorithm=ALGORITHM_AES_GCM)

print("Testing nonce uniqueness over 1,000 records...")

nonces = set()
for i in range(1000):
    protected = client.protect_record(f"Record {i}", f"seq:{i}")
    nonce = protected['nonce']
    
    if nonce in nonces:
        print(f"✗ ERROR: Nonce reuse detected at record {i}")
        break
    
    nonces.add(nonce)
    
    if (i + 1) % 250 == 0:
        print(f"  ✓ {i + 1} records, {len(nonces)} unique nonces")

print(f"✓ All {len(nonces)} nonces unique - no reuse")
EOF
```

---

### 6.2: Test Large Record

```bash
python3 << 'EOF'
from client.test_harness import TestHarness
from shared.config import ALGORITHM_AES_GCM

harness = TestHarness(algorithm=ALGORITHM_AES_GCM)

# Create 1 MB record
large_plaintext = "X" * (1024 * 1024)
print(f"Testing large record: {len(large_plaintext)} bytes...")

protected = harness.sender.protect_record(large_plaintext, "metadata")
print(f"✓ Encrypted successfully")

json_record = harness.sender.send_record(protected)
response = harness.receiver.process_protected_record(json_record)

if response['success'] and response['plaintext'] == large_plaintext:
    print(f"✓ Decrypted successfully")
    print(f"✓ Plaintext matches")
else:
    print(f"✗ Test failed")
EOF
```

---

### 6.3: Test Empty Record

```bash
python3 << 'EOF'
from client.test_harness import TestHarness
from shared.config import ALGORITHM_AES_GCM

harness = TestHarness(algorithm=ALGORITHM_AES_GCM)

# Create empty record
print("Testing empty record...")

protected = harness.sender.protect_record("", "metadata")
print(f"✓ Encrypted empty message")

json_record = harness.sender.send_record(protected)
response = harness.receiver.process_protected_record(json_record)

if response['success'] and response['plaintext'] == "":
    print(f"✓ Decrypted empty message successfully")
else:
    print(f"✗ Test failed")
EOF
```

---

### 6.4: Test Without AAD

```bash
python3 << 'EOF'
from client.test_harness import TestHarness
from shared.config import ALGORITHM_AES_GCM

harness = TestHarness(algorithm=ALGORITHM_AES_GCM)

# Create record without AAD
print("Testing record without AAD...")

protected = harness.sender.protect_record("Message without AAD")
print(f"✓ Created record: AAD = '{protected['aad']}'")

json_record = harness.sender.send_record(protected)
response = harness.receiver.process_protected_record(json_record)

if response['success']:
    print(f"✓ Successfully processed record without AAD")
else:
    print(f"✗ Failed: {response['error']}")
EOF
```

---

## Part 7: Troubleshooting

### Problem: "ModuleNotFoundError: No module named 'cryptography'"

**Solution:**
```bash
# Make sure venv is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt

# Verify
python3 -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; print('OK')"
```

---

### Problem: "Cannot find module 'client' or 'server'"

**Solution:**
```bash
# Make sure you're in the right directory
cd "/home/anandc2/Desktop/Crptography Assignment /Crptography/Assignment_one"

# Verify structure
ls -la shared/ server/ client/
```

---

### Problem: Tests run but show errors

**Solution:**
```bash
# Check Python version (should be 3.8+)
python3 --version

# Check if venv is activated
which python3
# Should show: /home/anandc2/Desktop/.../venv/bin/python3

# Reinstall everything
rm -rf venv/
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

### Problem: "Authentication verification failed" errors

**Solution:** This is actually expected in some tests (TR-2, TR-3, TR-4, TR-6). Those tests intentionally cause failures to verify they're caught.

Check for "✓ PASS" in the output - if it says PASS, the test is working correctly.

---

## Part 8: Deactivating Virtual Environment

When done testing, deactivate the virtual environment:

```bash
deactivate
```

The prompt should return to normal (without `(venv)`).

---

## Quick Commands Reference

```bash
# Navigate to project
cd "/home/anandc2/Desktop/Crptography Assignment /Crptography/Assignment_one"

# Activate venv
source venv/bin/activate

# Run all tests
python3 client/test_harness.py

# Run and save output
python3 client/test_harness.py 2>&1 | tee test_results.log

# View last 50 lines of output
tail -50 test_results.log

# Exit venv when done
deactivate
```

---

## Testing Checklist

Use this to track your manual testing:

- [ ] Virtual environment activated (`(venv)` in prompt)
- [ ] Dependencies verified (`pip list | grep cryptography`)
- [ ] Full test suite runs (`python3 client/test_harness.py`)
- [ ] All 8 tests pass for AES-GCM
- [ ] All 8 tests pass for ChaCha20-Poly1305
- [ ] Test output saved to file
- [ ] Individual components tested (crypto_engine, nonce_manager, etc.)
- [ ] Performance metrics collected
- [ ] Edge cases tested (empty, large, no AAD)
- [ ] Troubleshooting items resolved

---

## Success Indicators

You'll know everything is working when you see:

```
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

...

======================================================================
FINAL SUMMARY - BOTH ALGORITHMS
======================================================================

AES-GCM: 8/8 tests passed

ChaCha20-Poly1305: 8/8 tests passed
```

---

That's it! You now have complete control over the testing process. Good luck! 🚀
