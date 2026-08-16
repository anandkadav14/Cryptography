# CS6530 â€“ Applied Cryptography
## Assignment 1 Report  
### Secure Data Protection using AES-GCM and ChaCha20-Poly1305

**Course:** CS6530 â€“ Applied Cryptography (Julâ€“Nov 2026)  
**Institution:** IIT Madras  
**Deliverable:** D2 â€“ Assignment 1 Report  
**Evidence date (UTC):** 2026-08-16  

---

## 1. Design Summary

### 1.1 Objective
This assignment implements a secure data protection subsystem for generic chunked/packetized application records exchanged between a sender and a receiver. The subsystem supports two AEAD configurations with equivalent functional behaviour:

- AES-GCM  
- ChaCha20-Poly1305  

### 1.2 High-Level Architecture
The implementation uses three logical entities inside a single application (permitted by Assignment Â§3.3):

| Entity | Role |
|--------|------|
| **Sender** (`SenderClient`) | Protects application records (nonce, AAD, AEAD encrypt) |
| **Receiver** (`ReceiverServer`) | Replay check â†’ authentication â†’ decrypt â†’ recover |
| **Malicious Actor** | Tampers with ciphertext, tag, AAD, or replays records for testing |

Network communication is optional and was not required. Logical exchange of protected JSON records is used.

### 1.3 Processing Pipelines

**Sender (protect):**  
Application Record â†’ Record Processing â†’ Nonce Management â†’ Associated Data (AAD) â†’ Selected AEAD â†’ Protected Application Record  

**Receiver (recover):**  
Protected Application Record â†’ Replay Verification â†’ Authentication Verification â†’ Decryption â†’ Recovered Application Record  

### 1.4 Cryptographic Parameters
| Parameter | Value |
|-----------|-------|
| Key size | 256-bit (32 bytes), pre-shared |
| Nonce size | 96-bit (12 bytes) |
| Tag size | 128-bit (16 bytes) |
| Library | Python `cryptography` (AESGCM, ChaCha20Poly1305) |

Primitives (AES/ChaCha/GCM/Poly1305) are **not** implemented by hand; a standard library is used, as required.

### 1.5 Nonce Management Approach
Nonce format:

```text
12-byte nonce = 4-byte random session prefix || 8-byte monotonic counter
```

- Counter starts at a random 32-bit value each session, then increments by 1 per record.  
- This prevents nonce reuse under the same key during normal operation.  
- Documented and verified under **TR-7** (~10,000 records).

### 1.6 Associated Data (AAD) Selection
Canonical AAD bound into AEAD authentication:

```text
AAD = "seq=<sequence>|" || optional_user_metadata
```

Example:

- sequence = `0`  
- user metadata = `rohit`  
- AAD = `seq=0|rohit`  

This binds the sequence number into authentication so an attacker cannot change only the JSON `sequence` field to bypass replay detection.

### 1.7 Replay Handling Strategy
- Each protected record carries a monotonically increasing `sequence` number.  
- Receiver maintains a sliding window of accepted sequences (capacity 10,000).  
- **Check** for replay/out-of-order **before** decryption.  
- **Register** the sequence **only after successful authentication**.  
- Duplicate or previously accepted sequences are rejected; plaintext is never released on failure.

### 1.8 Implementation Assumptions
1. Sender and receiver already share a secret key (key establishment out of scope).  
2. Logical entities in one application are sufficient (network optional).  
3. Out-of-order delivery is treated as replay/reject (reliable ordering out of scope).  
4. Both AEAD algorithms provide equivalent subsystem behaviour; only the cipher differs.

### 1.9 Protected Record Format
```json
{
  "sequence": 0,
  "nonce": "<12-byte hex>",
  "ciphertext": "<hex>",
  "tag": "<16-byte hex>",
  "aad": "<canonical AAD hex>",
  "algorithm": "AES-GCM | ChaCha20-Poly1305",
  "plaintext_length": <int>
}
```

---

## 2. Testing Results (TR-1 to TR-8)

Unless noted, every Testing Requirement was executed **separately** for **AES-GCM** and **ChaCha20-Poly1305**.

**Automated harness:** `run_tests.py`  
**Evidence root:** `evidence/`  

### Master Outcome Table

| Algorithm | TR-1 | TR-2 | TR-3 | TR-4 | TR-5 | TR-6 | TR-7 | TR-8 |
|-----------|------|------|------|------|------|------|------|------|
| AES-GCM | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| ChaCha20-Poly1305 | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |

---

### TR-1 â€“ Positive Baseline Test (10%)

| Field | Content |
|-------|---------|
| **Objective** | Demonstrate successful protection, verification, and recovery of valid application records. |
| **Procedure** | Generate three different plaintexts under one shared key; protect; process at receiver; compare recovered plaintext. |
| **Test Input** | Plaintexts: `Hello Alice`, `Temp=27.5C`, `payload-chunk-001` with corresponding AAD metadata. |
| **Expected Behaviour** | All records authenticate and recover exact original plaintext. |
| **Observed Behaviour** | All three records recovered correctly for both algorithms. |
| **Outcome** | **PASS** (AES-GCM), **PASS** (ChaCha20-Poly1305) |
| **Supporting Evidence** | `evidence/AES-GCM/TR-1.txt`, `evidence/ChaCha20-Poly1305/TR-1.txt` |

---

### TR-2 â€“ Ciphertext Integrity Test (8%)

| Field | Content |
|-------|---------|
| **Objective** | Show that ciphertext modification causes authentication failure and rejection. |
| **Procedure** | Protect a valid record; flip bits in ciphertext (malicious actor); submit to receiver. |
| **Test Input** | Valid protected record with tampered ciphertext field. |
| **Expected Behaviour** | Authentication fails; plaintext not released. |
| **Observed Behaviour** | Receiver rejected tampered record for both algorithms. |
| **Outcome** | **PASS** / **PASS** |
| **Supporting Evidence** | `evidence/*/TR-2.txt` |

---

### TR-3 â€“ Authentication Tag Test (8%)

| Field | Content |
|-------|---------|
| **Objective** | Show that modification of the authentication tag causes rejection. |
| **Procedure** | Protect record; flip bits in tag; submit to receiver. |
| **Test Input** | Valid record with tampered 16-byte tag. |
| **Expected Behaviour** | Authentication fails; no plaintext release. |
| **Observed Behaviour** | Rejected for both algorithms. |
| **Outcome** | **PASS** / **PASS** |
| **Supporting Evidence** | `evidence/*/TR-3.txt` |

---

### TR-4 â€“ Associated Data (AAD) Test (8%)

| Field | Content |
|-------|---------|
| **Objective** | Show that AAD modification is detected and the record is rejected. |
| **Procedure** | Protect record with user metadata; tamper AAD bytes; submit to receiver. |
| **Test Input** | Original AAD includes `seq=<n>|...`; tampered AAD differs. |
| **Expected Behaviour** | Authentication / binding check fails; reject. |
| **Observed Behaviour** | Rejected for both algorithms. |
| **Outcome** | **PASS** / **PASS** |
| **Supporting Evidence** | `evidence/*/TR-4.txt` |

---

### TR-5 â€“ Replay Test (8%)

| Field | Content |
|-------|---------|
| **Objective** | Show replay of a previously accepted record is detected and handled. |
| **Procedure** | Protect one record; process twice at receiver with identical JSON. |
| **Test Input** | Same protected application record submitted twice. |
| **Expected Behaviour** | First accept; second reject as replay. |
| **Observed Behaviour** | First success; second `replay=true` with sequence already seen. |
| **Outcome** | **PASS** / **PASS** |
| **Supporting Evidence** | `evidence/*/TR-5.txt` |

---

### TR-6 â€“ Wrong-Key Test (8%)

| Field | Content |
|-------|---------|
| **Objective** | Show incorrect cryptographic key causes authentication failure. |
| **Procedure** | Encrypt with shared key K; decrypt with K (must succeed); decrypt with random wrong key (must fail). |
| **Test Input** | Correct 256-bit key vs random 256-bit key. |
| **Expected Behaviour** | Correct key recovers plaintext; wrong key fails auth. |
| **Observed Behaviour** | As expected for both algorithms. |
| **Outcome** | **PASS** / **PASS** |
| **Supporting Evidence** | `evidence/*/TR-6.txt` |

---

### TR-7 â€“ Nonce Management Verification (10%)

| Field | Content |
|-------|---------|
| **Objective** | Demonstrate nonce reuse does not occur during normal operation under one key. |
| **Procedure** | Protect approximately 10,000 records with the same key; collect nonces; check uniqueness. |
| **Test Input** | `NONCE_TEST_COUNT = 10000` application records. |
| **Expected Behaviour** | 10,000 unique nonces; no reuse. |
| **Observed Behaviour (AES-GCM)** | 10000 unique nonces; elapsed â‰ˆ 0.045 s; **PASS** |
| **Observed Behaviour (ChaCha20)** | 10000 unique nonces; **PASS** |
| **Outcome** | **PASS** / **PASS** |
| **Supporting Evidence** | `evidence/*/TR-7.txt` |

---

### TR-8 â€“ Performance Evaluation (15%)

| Field | Content |
|-------|---------|
| **Objective** | Compare protection and recovery performance for both AEAD configurations at required sizes. |
| **Procedure** | For sizes 64 B, 1 KiB, 64 KiB: measure encrypt + decrypt latency and throughput under equivalent conditions. |
| **Test Input** | Record sizes `[64, 1024, 65536]` bytes; same machine; Python `cryptography` backend. |
| **Expected Behaviour** | Measurements obtained for all three sizes for both algorithms. |
| **Observed Behaviour** | See Performance Analysis below. |
| **Outcome** | **PASS** / **PASS** |
| **Supporting Evidence** | `evidence/*/TR-8.txt`, `evidence/summary/TEST_SUMMARY.md` |

---

## 3. Supporting Evidence

| Artefact | Description |
|----------|-------------|
| `evidence/summary/TEST_SUMMARY.md` | Master Pass/Fail + TR-8 comparison table |
| `evidence/summary/TEST_SUMMARY.json` | Machine-readable full results |
| `evidence/AES-GCM/TR-*.txt` | Per-requirement console evidence (AES-GCM) |
| `evidence/ChaCha20-Poly1305/TR-*.txt` | Per-requirement console evidence (ChaCha20) |
| `run_tests.py` | Reproducible automated harness |

Interactive CLI evidence may additionally be captured from `python main.py` (menu options 2â€“7) for viva/screenshots.

**How to reproduce:**
```text
cd Assignment_one
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
python run_tests.py
```

---

## 4. Performance Analysis

Measurements from automated run on the development workstation (single-run timings; absolute values are machine-dependent).

| Size | AES-GCM total (ms) | AES-GCM (MB/s) | ChaCha20-Poly1305 total (ms) | ChaCha20 (MB/s) |
|------|-------------------:|---------------:|-----------------------------:|----------------:|
| 64 B | 0.054 | 1.141 | 0.047 | 1.307 |
| 1 KiB | 0.032 | 30.422 | 0.053 | 18.322 |
| 64 KiB | 0.375 | 166.711 | 0.422 | 147.929 |

### Observations
1. Both algorithms correctly protect and recover all required sizes.  
2. At small sizes (64 B), fixed per-call overhead dominates; throughput appears low for both.  
3. At 64 KiB, throughput rises substantially for both configurations (AES-GCM slightly higher in this run).  
4. Relative ranking can vary by CPU AES-NI availability, Python overhead, and OS load; the important result is **comparable functional behaviour** with measurable performance characteristics under equivalent conditions.  
5. For the report/viva: emphasise engineering correctness (nonce/AAD/replay) alongside these numbers.

---

## 5. Discussion

### 5.1 What the subsystem achieves
The implementation meets the Functional and Security Requirements by combining library AEAD with engineered nonce management, AAD binding of sequence numbers, and replay detection with delayed commit after authentication success.

### 5.2 Why sequence is included in AAD
Without binding sequence into AAD, an adversary could replay a valid ciphertext while changing only the JSON sequence field. Binding `seq=<n>|` into AAD ensures such manipulation fails authentication or binding checks.

### 5.3 Why replay state is committed after auth
Registering a sequence before successful decrypt would allow an attacker to â€œburnâ€ sequence numbers with invalid ciphertexts and cause denial of honest records. Committing only after success avoids that failure mode.

### 5.4 Scope boundaries respected
Key exchange, PKI, transport reliability, and primitive implementation were correctly treated as out of scope.

### 5.5 Limitations / future work
- Interactive CLI performance table can interleave logs; automated harness provides cleaner TR-8 evidence.  
- Optional enhancements (not required): networked sender/receiver processes; HTML GUI.  
- For submission packaging: convert this Markdown report to PDF if Moodle requires PDF format.

---

## 6. Conclusion
The secure data protection subsystem supports AES-GCM and ChaCha20-Poly1305 with equivalent behaviour, documents nonce/AAD/replay design choices, and has been validated against TR-1 through TR-8 for both configurations with archived evidence.

---

## Appendix A â€“ Assessment Mapping

| Assessment Component | Weight | Status |
|----------------------|-------:|--------|
| TR-1 Positive Baseline | 10% | Demonstrated (both algos) |
| TR-2 Ciphertext Integrity | 8% | Demonstrated (both algos) |
| TR-3 Authentication Tag | 8% | Demonstrated (both algos) |
| TR-4 AAD Test | 8% | Demonstrated (both algos) |
| TR-5 Replay Test | 8% | Demonstrated (both algos) |
| TR-6 Wrong-Key Test | 8% | Demonstrated (both algos) |
| TR-7 Nonce Management | 10% | Demonstrated (~10k, both algos) |
| TR-8 Performance Evaluation | 15% | Demonstrated (64B/1KiB/64KiB, both) |
| Assignment 1 Report | 15% | This document |
| Individual Viva | 10% | Prepare from Design + Discussion sections |

## Appendix B â€“ Software Requirements (D3 pointer)
See `Assignment_one/README.md` for software requirements, library list, build, and execution instructions. Primary dependency: `cryptography>=41.0.0`.
