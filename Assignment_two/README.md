# CS6530 Assignment 2

Authenticated Ephemeral Key Establishment (X25519, Ed25519, SHA-256, HKDF-SHA-256, AES-256-GCM).

Alice and Bob run on **two different computers**. This folder contains the full protocol code. Use instructor `transport.py` for TCP framing only.

---

## Setup

```powershell
cd Assignment_two
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python generate_keys.py
```

Roll numbers in `config.py` (8 ASCII chars each):
- Alice: `IC43333 `
- Bob: `IC43332 `

---

## Step 0 — connectivity (no crypto)

**Bob machine:**
```powershell
python bob_test.py
```

**Alice machine:**
```powershell
python alice_test.py <BOB_IP>
```

---

## Step 1 — normal authenticated session (TR-1)

**Bob machine:**
```powershell
python bob/bob.py
```

**Alice machine:**
```powershell
python alice/alice.py <BOB_IP>
```

Expected: M1–M4 SUCCESS, three protected messages each direction, counters 0/1/2.

---

## Step 2 — local automated checks (one PC)

```powershell
python run_tests.py
```

Runs HKDF check, replay rejection (TR-3 logic), forward-secrecy logic (TR-4), and a localhost TR-1 run.

---

## Step 3 — MITM demo (TR-2)

Weakened mode (auth off) — Mallory substitutes ephemeral keys:

Terminal 1 (Bob, port 5001):
```powershell
python bob/bob.py --port 5001 --no-auth
```

Terminal 2 (Mallory, listens 5000, forwards to Bob 5001):
```powershell
python mallory/mallory.py --listen-port 5000 --bob-port 5001
```

Terminal 3 (Alice connects to Mallory):
```powershell
python alice/alice.py 127.0.0.1 --no-auth
```

Full auth mode: run same layout **without** `--no-auth`. Signature verification should fail and session aborts.

---

## Project layout

```
Assignment_two/
  transport.py          instructor TCP helper (unchanged)
  alice_test.py         connectivity test
  bob_test.py           connectivity test
  generate_keys.py      Ed25519 identity keys
  run_tests.py          local TR checks
  config.py             protocol constants
  crypto/               shared handshake + AEAD code
  alice/alice.py        Alice program
  bob/bob.py            Bob program
  mallory/mallory.py    MITM proxy for TR-2
  keys/                 identity keys (private keys stay local)
```

---

## Two-machine checklist (with teammate)

1. Both pull same repo
2. Run `python generate_keys.py` once; copy trusted public keys to both machines
3. Bob runs `bob/bob.py`
4. Alice runs `alice/alice.py <BOB_IP>`
5. Capture logs for report
6. Repeat TR-2 / TR-3 / TR-4 demos
7. Optional Wireshark bonus on a successful session

---

## Notes

- Do not use TLS or implement primitives by hand.
- X25519 and Ed25519 are separate key pairs.
- Receiver accepts only the next expected counter (replay rejection).
- Raw X25519 shared secret is never used directly as AES key.
