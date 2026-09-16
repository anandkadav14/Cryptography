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
- `keys/trusted/` — public keys both sides trust

**Important for two PCs:** Alice and Bob must share the **same** trusted public keys.

- Easy way: run `generate_keys.py` on **one** PC, then copy the whole `keys/` folder to the other PC (USB / shared drive / zip).
- Or: generate once, copy only `keys/trusted/` plus each role’s private key to the correct machine.

### 4. Optional — check on one PC first

```bash
python run_tests.py
```

You should see HKDF / TR-3 / TR-4-logic / TR-1-local all **PASS**.

---

## Two-machine run (main assignment path)

Agree who is **Alice** and who is **Bob**. Find Bob’s IP (example Windows: `ipconfig`).

Default port: **5000**. Allow it in the firewall if needed.

### Step A — Connectivity only (no crypto)

**Bob PC:**

```bash
python bob_test.py
```

**Alice PC:**

```bash
python alice_test.py <BOB_IP>
```

Expected: Alice sends `Hello Bob`, Bob replies `Hello Alice`.

### Step B — Full authenticated session (TR-1)

**Bob PC first:**

```bash
python bob/bob.py
```

**Alice PC:**

```bash
python alice/alice.py <BOB_IP>
```

Expected in both terminals:

- M1 → M2 → M3 → M4 with **SUCCESS**
- Three protected APP messages each way (counters 0, 1, 2)
- Session complete

Keep these terminal logs / screenshots for the report.

---

## Other demos

### Local MITM sketch (TR-2) — one PC, three terminals

**Terminal 1 — Bob (port 5001), auth off:**

```bash
python bob/bob.py --port 5001 --no-auth
```

**Terminal 2 — Mallory:**

```bash
python mallory/mallory.py --listen-port 5000 --bob-port 5001
```

**Terminal 3 — Alice → Mallory:**

```bash
python alice/alice.py 127.0.0.1 --no-auth
```

Then repeat **without** `--no-auth` (and with Mallory `--auth-attack` if you use that mode). With full authentication, the forged ephemeral keys should cause signature failure / abort.

### Replay (TR-3)

Covered in `run_tests.py` (same record rejected when counter is stale). Live demo: capture an APP record and resend it; Bob/Alice should reject.

### Forward secrecy (TR-4)

Covered in `run_tests.py` logic. Live demo: save session material, discard ephemeral secrets, show long-term Ed25519 alone cannot rebuild traffic keys; old ephemeral secret could.

### Wireshark bonus (optional)

Capture one successful Alice–Bob session. Label M1–M4 and at least one AES-GCM application record. Note what is visible on the wire vs what is not.

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
├── run_tests.py              one-PC checks
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
