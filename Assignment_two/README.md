# CS6530 Assignment 2 — Authenticated Ephemeral Key Establishment

Course: Applied Cryptography (IIT Madras)

Alice and Bob run on **two different computers** on the same network. They complete an authenticated handshake (X25519 + Ed25519), derive session keys with HKDF-SHA-256, then exchange AES-256-GCM protected messages.

This folder uses the instructor TCP helper (`transport.py`) for framing only. Crypto is implemented in our code.

**Branch tip:** use the `assignment-two` branch if that is where this code lives on GitHub.

---

## What you need

| Item | Detail |
|------|--------|
| Python | 3.10 or newer |
| OS | Windows, Linux, or macOS |
| Network | Two PCs that can reach each other (same LAN / Wi-Fi) |
| Library | `cryptography` (see `requirements.txt`) |

---

## After cloning the repository

### 1. Get the code

```bash
git clone https://github.com/anandkadav14/Cryptography.git
cd Cryptography
git checkout assignment-two
cd Assignment_two
```

### 2. Create a virtual environment and install packages

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

### 3. Create identity keys

Private keys are **not** stored in git. Each machine (or one shared setup) must generate them:

```bash
python generate_keys.py
```

This creates:

- `keys/alice/` — Alice Ed25519 private + public
- `keys/bob/` — Bob Ed25519 private + public
- `keys/trusted/` — public keys both sides trust (copies, not a new keypair)

Diagram: [`docs/key_generation.md`](docs/key_generation.md)

**Important for two PCs:** Alice and Bob must share the **same** trusted public keys.

- Easy way: run `generate_keys.py` on **one** PC, then copy the whole `keys/` folder to the other PC (USB / shared drive / zip).
- Or: generate once, copy only `keys/trusted/` plus each role’s private key to the correct machine.

### 4. Optional — check on one PC first

```bash
python run_tests.py
```

You should see HKDF / TR-3 / TR-4-logic / TR-1-local all **PASS**.

---

## Two-machine run (PDF path)

This PC = **Bob** (example IP `10.21.232.147`). Other laptop = **Alice**. Same `keys/` on both. Mallory/replay is an extra **process on Bob’s PC**, not a third laptop.

Copy updated `Assignment_two` code to the Alice laptop after pulls (keep the same `keys/`).

### Step A — Connectivity

**Bob:** `python bob_test.py`  
**Alice:** `python alice_test.py <BOB_IP>`

### TR-1 — Normal authenticated session

**Bob:** `python bob/bob.py`  
**Alice:** `python alice/alice.py <BOB_IP>`

### TR-2 — MITM (Alice → Bob-PC:5000 Mallory → Bob:5001)

Weak (auth off). Bob PC two terminals + Alice laptop:

```bash
python bob/bob.py --port 5001 --no-auth
python mallory/mallory.py --listen-port 5000 --bob-port 5001 --weak
python alice/alice.py <BOB_IP> --no-auth
```

Bob must show `MALLORY-EDITED:` in decrypted APP plaintext.

Auth on (same swap, session abort):

```bash
python bob/bob.py --port 5001
python mallory/mallory.py --listen-port 5000 --bob-port 5001
python alice/alice.py <BOB_IP>
```

### TR-3 — Live replay

```bash
python bob/bob.py --port 5001
python tr3_replay.py --listen-port 5000 --bob-port 5001
python alice/alice.py <BOB_IP>
```

Bob: original APP SUCCESS, replay `REJECTED`.

### TR-4 — Forward secrecy

```bash
python bob/bob.py --save-s1 s1_record.json
python alice/alice.py <BOB_IP>
python tr4_forward_secrecy.py s1_record.json
```

### Wireshark bonus

Capture on Bob during TR-1. Identify M1–M4 and one APP record.

Local extra check: `python run_tests.py`

---

## Project layout

```
Assignment_two/
├── README.md                 this file
├── SETUP_GUIDE.md            short clone-to-run checklist
├── requirements.txt
├── transport.py              instructor TCP helper (do not change for crypto)
├── alice_test.py             plain Hello connectivity
├── bob_test.py
├── generate_keys.py
├── docs/key_generation.md    what the key files are
├── tr3_replay.py             PDF TR-3 live capture/replay
├── tr4_forward_secrecy.py    PDF TR-4 recorded S1 analysis
├── run_tests.py              extra one-PC checks
├── config.py                 protocol IDs, roll numbers, port
├── crypto/                   shared handshake + AEAD
├── alice/alice.py
├── bob/bob.py
├── mallory/mallory.py
└── keys/                     generated locally (private keys gitignored)
```

---

## Config notes

In `config.py`:

- `ALICE_ID` / `BOB_ID` — exactly 8 ASCII bytes (roll numbers)
- `PORT` — default `5000`

Change IDs only if your team’s official rolls differ, and keep both machines on the same values.

---

## Common problems

| Problem | What to try |
|---------|-------------|
| Connection refused | Bob must start first; check IP and port; check firewall |
| Hello works, crypto fails | Keys mismatch — copy the same `keys/` tree to both PCs |
| Module not found | Activate `venv` and `pip install -r requirements.txt` |
| Wrong Python | Use the venv Python (`python --version` after activate) |

---

## Rules from the assignment

- Use standard libraries; do not implement X25519 / Ed25519 / HKDF / AES-GCM yourself
- Do not solve this with TLS
- No PKI / certificates required; long-term public keys are assumed authentic for this task
- Marks are for crypto correctness and demos, not UI
