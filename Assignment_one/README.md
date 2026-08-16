# Secure Data Protection Subsystem

**Course:** CS6530 Applied Cryptography (IIT Madras)  
**Assignment:** 1

This project is a secure data protection subsystem built with authenticated encryption (AEAD). It supports **AES-GCM** and **ChaCha20-Poly1305**.

It covers:

- shared-key encryption and decryption
- nonce management (unique nonces under one key)
- associated authenticated data (AAD)
- replay detection

Sender and receiver run together in one interactive CLI. You do not need a separate network server for the assignment tests.

---

## 1. Software requirements

| Item | Details |
|------|---------|
| OS | Windows, Linux, or macOS |
| Language | Python 3.10 or newer (3.11+ preferred) |
| Tooling | `pip` (included with Python) |

Using a virtual environment (`venv`) is recommended so packages stay inside this project folder.

---

## 2. Libraries

One third-party library:

```
cryptography>=41.0.0
```

Listed in `requirements.txt`. AES-GCM and ChaCha20-Poly1305 come from this library. The assignment does not re-implement the cipher primitives.

---

## 3. Project structure

```
Cryptography/
├── README.md                 # Short intro to the repo; points to Assignment_one
├── .gitignore                # Tells git which local files to ignore (venv, cache, temp files)
└── Assignment_one/
    ├── README.md             # Full guide: install steps, libraries used, how to run and test
    ├── main.py               # Starts the app menu so you can pick an algorithm and try encrypt/decrypt by hand
    ├── run_tests.py          # Automatically runs all required tests (TR-1 to TR-8) for AES-GCM and ChaCha20
    ├── run_tests.sh          # One-command helper on Linux/macOS that just runs run_tests.py
    ├── requirements.txt      # Dependency list; install with pip so Python has the cryptography library
    ├── client/               # Sender code: takes plaintext, adds nonce/AAD, encrypts, builds the packet
    ├── server/               # Receiver code: checks replay, verifies authenticity, then decrypts safely
    ├── shared/               # Shared modules both sides use (crypto engine, nonce, replay, AAD, config)
    ├── evidence/             # Folder of saved test result logs; useful for submission, not needed to run the app
    └── docs/                 # Place for your written report draft; not part of the running program
```

Inside `shared/`:

| File | Role |
|------|------|
| `crypto_engine.py` | Encrypt / decrypt with AES-GCM or ChaCha20-Poly1305 |
| `nonce_manager.py` | Creates unique nonces for each record |
| `replay_detector.py` | Rejects packets that were already accepted |
| `aad_utils.py` | Binds the sequence number into AAD |
| `config.py` | Key size, nonce size, test constants |

`venv/` may appear after setup. Keep it local; do not treat it as submission source.

---

## 4. Build / setup

Open a terminal in the `Assignment_one` folder, then:

**Windows (PowerShell)**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Linux / macOS**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

There is no separate compile step. After `pip install`, the project is ready.

---

## 5. How to run

### Interactive CLI (manual testing)

```bash
python main.py
```

Suggested flow:

1. Select algorithm: AES-GCM or ChaCha20-Poly1305.
2. Encrypt a plaintext (AAD optional).
3. Send / process the packet on the receiver side.
4. Use menu options for TR-1 to TR-8 (normal decrypt, tamper tests, wrong key, replay, nonce stress, size checks).

Run the same checks for **both** algorithms.

### Automated tests

```bash
python run_tests.py
```

On Linux/macOS you can also use:

```bash
bash run_tests.sh
```

This runs TR-1 to TR-8 for both algorithms and writes logs under `evidence/`. Summary: `evidence/summary/TEST_SUMMARY.md`.

---

## 6. How the system works (short)

1. Sender and receiver share one 256-bit key in the CLI session.
2. Each record gets a fresh 96-bit (12-byte) nonce.
3. Optional user AAD is supported; the sequence number is also bound into AAD.
4. Receiver order: **replay check → authentication → decrypt**.
5. A nonce is marked as seen only after authentication succeeds.
6. The same application logic is used for AES-GCM and ChaCha20-Poly1305; only the AEAD mode changes.

---

## 7. Test requirements covered

| ID | Check |
|----|--------|
| TR-1 | Correct encrypt and decrypt |
| TR-2 | Ciphertext tampering is rejected |
| TR-3 | AAD tampering is rejected |
| TR-4 | Replay is rejected |
| TR-5 | Wrong / mismatched algorithm handling |
| TR-6 | Wrong key is rejected |
| TR-7 | Many unique nonces (default 10,000) |
| TR-8 | Record sizes 64 B, 1 KiB, 64 KiB |

---

## 8. Notes for submission

- Main code to submit: `client/`, `server/`, `shared/`, `main.py`, `run_tests.py`, `requirements.txt`, `README.md`
- `evidence/` is optional (regenerate with `python run_tests.py` if needed)
- `docs/` is only for report drafting
- `venv/` should not be uploaded
