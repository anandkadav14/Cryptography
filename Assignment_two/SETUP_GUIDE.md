# Setup guide — after you clone

Short checklist so anyone can run Assignment 2 on a new machine.

## 1. Clone and open the folder

```bash
git clone https://github.com/anandkadav14/Cryptography.git
cd Cryptography
git checkout assignment-two
cd Assignment_two
```

## 2. Install Python packages

```bash
python -m venv venv
```

Windows:

```powershell
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Linux / macOS:

```bash
source venv/bin/activate
pip install -r requirements.txt
```

## 3. Keys (required)

Private keys are not in the repo.

**Option A — one person generates, both use the same folder**

```bash
python generate_keys.py
```

Zip/copy the whole `keys/` folder to the second PC. Put it inside `Assignment_two/keys/`.

**Option B — each PC generates (only for solo local tests)**

```bash
python generate_keys.py
```

For real Alice–Bob auth on two PCs, Option A is safer (same trusted public keys).

## 4. Quick self-check (one PC)

```bash
python run_tests.py
```

All lines should say **PASS**.

## 5. Two PCs on the same network

1. Decide: who is Alice, who is Bob  
2. Note Bob’s IP address  
3. Same `keys/` on both machines  
4. Same code (`git pull` on `assignment-two`)

### Connectivity test

Bob:

```bash
python bob_test.py
```

Alice:

```bash
python alice_test.py <BOB_IP>
```

### Real session (TR-1)

Bob:

```bash
python bob/bob.py
```

Alice:

```bash
python alice/alice.py <BOB_IP>
```

Screenshot both terminals when you see SUCCESS for M1–M4 and APP messages.

## 6. More detail

See `README.md` in this folder for MITM, replay, forward secrecy, Wireshark bonus, and troubleshooting.
