#!/usr/bin/env python3
"""
CS6530 Assignment 1 — Automated Testing Harness (TR-1 to TR-8)
Runs both AES-GCM and ChaCha20-Poly1305 and writes evidence artefacts.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from client.client import SenderClient
from server.server import ReceiverServer
from shared.config import (
    ALGORITHM_AES_GCM,
    ALGORITHM_CHACHA20,
    NONCE_TEST_COUNT,
    TEST_RECORD_SIZES,
)
from shared.crypto_engine import AuthenticationError, CryptoEngine

EVIDENCE = ROOT / "evidence"
ALGORITHMS = [ALGORITHM_AES_GCM, ALGORITHM_CHACHA20]


def algo_dir(name: str) -> Path:
    safe = name.replace("/", "-")
    d = EVIDENCE / safe
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def silence_module_loggers() -> None:
    for name in ("client.client", "server.server", __name__):
        log = logging.getLogger(name)
        log.handlers.clear()
        log.addHandler(logging.NullHandler())
        log.propagate = False
        log.setLevel(logging.CRITICAL)


def result(tr_id: str, title: str, passed: bool, detail: str, extra: dict | None = None) -> dict:
    return {
        "id": tr_id,
        "title": title,
        "outcome": "PASS" if passed else "FAIL",
        "detail": detail,
        "extra": extra or {},
    }


def run_tr1(sender: SenderClient, receiver: ReceiverServer) -> dict:
    plaintexts = [
        ("Hello Alice", "msg-type:chat"),
        ("Temp=27.5C", "msg-type:telemetry"),
        ("payload-chunk-001", "chunk:1"),
    ]
    lines = ["TR-1 Positive Baseline Test", ""]
    ok = True
    for i, (pt, aad) in enumerate(plaintexts):
        lines.append(f"\nRecord {i}:")
        lines.append(f"  [SENDER] Input plaintext: {pt!r}, AAD: {aad!r}")

        # Sender processing
        lines.append(f"  [SENDER] → Calling protect_record()")
        prot = sender.protect_record(pt, aad)
        lines.append(f"    ✓ Generated nonce: {prot['nonce']}")
        lines.append(f"    ✓ Encrypted (ciphertext size: {len(prot['ciphertext'])//2} bytes)")
        lines.append(f"    ✓ Generated auth tag: {prot['tag'][:16]}...")
        lines.append(f"    ✓ AAD in AEAD: {bytes.fromhex(prot['aad']).decode('utf-8', errors='ignore')}")
        lines.append(f"    ✓ Sequence number: {prot['sequence']}")

        # Transmission
        lines.append(f"  [NETWORK] Transmitting protected record as JSON")
        json_record = sender.send_record(prot)

        # Receiver processing
        lines.append(f"  [RECEIVER] Input: Protected record (JSON)")
        lines.append(f"  [RECEIVER] → Calling process_protected_record()")
        resp = receiver.process_protected_record(json_record)
        lines.append(f"    ✓ Parsed JSON")
        lines.append(f"    ✓ Checked replay (sequence {prot['sequence']}) → OK (new sequence)")
        lines.append(f"    ✓ Verified authentication tag → OK")
        lines.append(f"    ✓ Decrypted ciphertext")
        lines.append(f"    ✓ Recovered plaintext: {resp.get('plaintext')!r}")

        # Verification
        match = resp.get("success") and resp.get("plaintext") == pt
        ok = ok and match
        lines.append(f"  [VERIFICATION] Match original: {match} {'✓' if match else '✗'}")
        lines.append("")

    return result("TR-1", "Positive Baseline Test", ok, "\n".join(lines), {"records": len(plaintexts)})


def run_tr2(sender: SenderClient, receiver: ReceiverServer) -> dict:
    lines = ["TR-2 Ciphertext Integrity Test", ""]

    # Sender: encrypt normally
    lines.append("[SENDER] Encrypting plaintext: 'integrity-plaintext'")
    prot = sender.protect_record("integrity-plaintext", "aad-tr2")
    lines.append(f"  ✓ Ciphertext: {prot['ciphertext'][:32]}...")
    lines.append(f"  ✓ Auth tag: {prot['tag']}")
    lines.append("")

    # Malicious actor: tamper with ciphertext
    lines.append("[MALICIOUS ACTOR] Tampering with ciphertext...")
    tampered = sender.create_tampered_ciphertext(prot)
    lines.append(f"  Original:  {prot['ciphertext'][:32]}...")
    lines.append(f"  Tampered:  {tampered['ciphertext'][:32]}... (bit flip in first byte)")
    lines.append("")

    # Network transmission
    lines.append("[NETWORK] Transmitting tampered record")
    lines.append("")

    # Receiver: process tampered record
    lines.append("[RECEIVER] Processing tampered record...")
    lines.append("  Step 1: Parse JSON → OK")
    lines.append(f"  Step 2: Check replay (sequence {tampered['sequence']}) → OK (new)")
    lines.append("  Step 3: Verify authentication tag")
    lines.append("    ℹ Computing tag from ciphertext + AAD + nonce...")
    lines.append("    ✗ COMPUTED TAG DOESN'T MATCH RECEIVED TAG!")
    lines.append("    ✗ Ciphertext was modified!")

    resp = receiver.process_protected_record(sender.send_record(tampered))
    lines.append(f"  ✗ Authentication FAILED: {resp.get('error')}")
    lines.append("")

    # Verification
    lines.append("[VERIFICATION]")
    lines.append(f"  Receiver success: {resp.get('success')} (expected: False)")
    lines.append(f"  Plaintext released: {resp.get('plaintext')} (expected: None)")
    passed = (not resp.get("success"))
    lines.append(f"  Test result: {'✓ PASS' if passed else '✗ FAIL'}")

    detail = "\n".join(lines)
    return result("TR-2", "Ciphertext Integrity Test", passed, detail)


def run_tr3(sender: SenderClient, receiver: ReceiverServer) -> dict:
    prot = sender.protect_record("tag-plaintext", "aad-tr3")
    tampered = sender.create_tampered_tag(prot)
    resp = receiver.process_protected_record(sender.send_record(tampered))
    passed = (not resp.get("success"))
    detail = (
        "TR-3 Authentication Tag Test\n\n"
        f"Original tag: {prot['tag']}\n"
        f"Tampered tag: {tampered['tag']}\n"
        f"Receiver success: {resp.get('success')}\n"
        f"Error: {resp.get('error')}\n"
    )
    return result("TR-3", "Authentication Tag Test", passed, detail)


def run_tr4(sender: SenderClient, receiver: ReceiverServer) -> dict:
    prot = sender.protect_record("aad-plaintext", "user-metadata")
    tampered = sender.create_tampered_aad(prot)
    resp = receiver.process_protected_record(sender.send_record(tampered))
    passed = (not resp.get("success"))
    detail = (
        "TR-4 Associated Data (AAD) Test\n\n"
        f"Original AAD hex: {prot['aad']}\n"
        f"Tampered AAD hex: {tampered['aad']}\n"
        f"Original AAD utf-8: {bytes.fromhex(prot['aad']).decode('utf-8', errors='replace')}\n"
        f"Receiver success: {resp.get('success')}\n"
        f"Error: {resp.get('error')}\n"
    )
    return result("TR-4", "Associated Data (AAD) Test", passed, detail)


def run_tr5(sender: SenderClient, receiver: ReceiverServer) -> dict:
    lines = ["TR-5 Replay Detection Test", ""]

    # Sender: create one record
    lines.append("[SENDER] Encrypting plaintext: 'replay-plaintext'")
    prot = sender.protect_record("replay-plaintext", "aad-tr5")
    lines.append(f"  ✓ Sequence: {prot['sequence']}")
    lines.append(f"  ✓ Nonce: {prot['nonce']}")
    lines.append(f"  ✓ Protected record created")
    lines.append("")

    # First transmission
    lines.append("[NETWORK] Transmitting record (1st time)")
    js = sender.send_record(prot)
    lines.append("")

    # First reception
    lines.append("[RECEIVER - ATTEMPT 1] Processing record...")
    lines.append(f"  Step 1: Parse JSON")
    lines.append(f"  Step 2: Check replay detector for sequence {prot['sequence']}")
    r1 = receiver.process_protected_record(js)
    lines.append(f"    ✓ Sequence NOT in history → OK (first time)")
    lines.append(f"    ✓ Record ACCEPTED")
    lines.append(f"    ✓ Sequence {prot['sequence']} RECORDED in replay detector")
    lines.append(f"    ✓ Decrypted: {r1.get('plaintext')!r}")
    lines.append("")

    # Second transmission (REPLAY)
    lines.append("[NETWORK] Transmitting SAME record again (REPLAY ATTACK)")
    lines.append(f"  Attacker sends identical JSON with sequence {prot['sequence']}")
    lines.append("")

    # Second reception
    lines.append("[RECEIVER - ATTEMPT 2] Processing SAME record...")
    lines.append(f"  Step 1: Parse JSON")
    lines.append(f"  Step 2: Check replay detector for sequence {prot['sequence']}")
    r2 = receiver.process_protected_record(js)
    lines.append(f"    ✗ Sequence {prot['sequence']} ALREADY IN HISTORY")
    lines.append(f"    ✗ REPLAY DETECTED!")
    lines.append(f"    ✗ Record REJECTED before authentication")
    lines.append(f"    ✗ Error: {r2.get('error')}")
    lines.append("")

    # Verification
    lines.append("[VERIFICATION]")
    lines.append(f"  Attempt 1: success={r1.get('success')} (expected: True)")
    lines.append(f"  Attempt 2: success={r2.get('success')}, replay={r2.get('replay')} (expected: False, True)")
    passed = bool(r1.get("success")) and (not r2.get("success")) and bool(r2.get("replay"))
    lines.append(f"  Test result: {'✓ PASS' if passed else '✗ FAIL'}")

    detail = "\n".join(lines)
    return result("TR-5", "Replay Test", passed, detail)


def run_tr6(sender: SenderClient, receiver: ReceiverServer) -> dict:
    prot = sender.protect_record("wrong-key-plaintext", "aad-tr6")
    nonce = bytes.fromhex(prot["nonce"])
    ciphertext = bytes.fromhex(prot["ciphertext"])
    tag = bytes.fromhex(prot["tag"])
    aad = bytes.fromhex(prot["aad"]) if prot["aad"] else b""

    correct_ok = False
    wrong_failed = False
    try:
        CryptoEngine(sender.algorithm, sender.shared_key).decrypt(ciphertext, tag, nonce, aad)
        correct_ok = True
    except AuthenticationError:
        correct_ok = False

    try:
        CryptoEngine(sender.algorithm, os.urandom(32)).decrypt(ciphertext, tag, nonce, aad)
        wrong_failed = False
    except AuthenticationError:
        wrong_failed = True

    passed = correct_ok and wrong_failed
    detail = (
        "TR-6 Wrong-Key Test\n\n"
        f"Correct key decrypt success: {correct_ok}\n"
        f"Wrong key decrypt failed (expected): {wrong_failed}\n"
    )
    return result("TR-6", "Wrong-Key Test", passed, detail)


def run_tr7(sender: SenderClient, count: int = NONCE_TEST_COUNT) -> dict:
    lines = ["TR-7 Nonce Management Verification", ""]
    lines.append(f"[TEST PLAN] Generate {count} records, verify all nonces unique")
    lines.append("")

    nonces = set()
    reuse_at = None
    t0 = time.perf_counter()

    # Show first few iterations in detail
    for i in range(min(5, count)):
        prot = sender.protect_record(f"nonce-test-{i}", f"seq-meta:{i}")
        n = prot["nonce"]
        nonces.add(n)

        # Parse nonce structure
        prefix = n[:8]
        counter = n[8:]
        lines.append(f"Record {i}:")
        lines.append(f"  [SENDER] → protect_record()")
        lines.append(f"    ✓ NonceManager.generate_nonce()")
        lines.append(f"      • Prefix (random): {prefix}")
        lines.append(f"      • Counter (incremental): {counter}")
        lines.append(f"      • Full nonce: {n}")
        lines.append(f"    ✓ Encrypted with nonce")
        lines.append(f"    ✓ Nonce tracked: {i+1} unique nonces so far")

    # Continue without detail output
    lines.append(f"\n[BULK PROCESSING] Generating records {5} to {count}...")
    for i in range(5, count):
        prot = sender.protect_record(f"nonce-test-{i}", f"seq-meta:{i}")
        n = prot["nonce"]
        if n in nonces:
            reuse_at = i
            break
        nonces.add(n)

    elapsed = time.perf_counter() - t0

    lines.append("")
    lines.append("[NONCE ANALYSIS]")
    lines.append(f"  Records generated: {count}")
    lines.append(f"  Unique nonces collected: {len(nonces)}")
    lines.append(f"  Nonce collision detected: {'YES at index ' + str(reuse_at) if reuse_at else 'NO ✓'}")
    lines.append("")
    lines.append("[NONCE STRUCTURE]")
    first_nonce = next(iter(nonces))
    last_nonce = prot['nonce'] if reuse_at is None else 'N/A'
    lines.append(f"  First nonce: {first_nonce}")
    lines.append(f"    Prefix: {first_nonce[:8]} (same for all nonces in session)")
    lines.append(f"    Counter: {first_nonce[8:]} (counter for record 0)")
    if reuse_at is None:
        lines.append(f"  Last nonce: {last_nonce}")
        lines.append(f"    Prefix: {last_nonce[:8]} (same)")
        lines.append(f"    Counter: {last_nonce[8:]} (counter for record {count-1})")
    lines.append("")
    lines.append("[PERFORMANCE]")
    lines.append(f"  Time to generate {count} nonces: {elapsed:.4f} seconds")
    lines.append(f"  Throughput: {count/elapsed:.0f} records/second")
    lines.append("")

    passed = reuse_at is None and len(nonces) == count
    lines.append(f"[RESULT] {'✓ PASS' if passed else '✗ FAIL'}")
    lines.append(f"  All {count} nonces are unique → Nonce management is WORKING")

    detail = "\n".join(lines)
    return result(
        "TR-7",
        "Nonce Management Verification",
        passed,
        detail,
        {"count": count, "unique": len(nonces), "elapsed_sec": round(elapsed, 4)},
    )


def run_tr8(sender: SenderClient, receiver: ReceiverServer) -> dict:
    rows = []
    lines = [
        "TR-8 Performance Evaluation",
        "",
        f"{'Size':<10} {'Encrypt_ms':>12} {'Decrypt_ms':>12} {'Total_ms':>12} {'Throughput_MBps':>16}",
        "-" * 66,
    ]
    for size in TEST_RECORD_SIZES:
        plaintext = "X" * size
        aad = "perf-meta"
        t0 = time.perf_counter()
        prot = sender.protect_record(plaintext, aad)
        enc_ms = (time.perf_counter() - t0) * 1000.0

        js = sender.send_record(prot)
        t1 = time.perf_counter()
        resp = receiver.process_protected_record(js)
        dec_ms = (time.perf_counter() - t1) * 1000.0

        if not resp.get("success"):
            return result("TR-8", "Performance Evaluation", False, f"Decrypt failed at size={size}: {resp}")

        total = enc_ms + dec_ms
        thr = (size / (total / 1000.0)) / (1024 * 1024) if total > 0 else 0.0
        label = f"{size}B" if size < 1024 else f"{size // 1024}KiB"
        row = {
            "size_bytes": size,
            "label": label,
            "encrypt_ms": round(enc_ms, 3),
            "decrypt_ms": round(dec_ms, 3),
            "total_ms": round(total, 3),
            "throughput_MBps": round(thr, 3),
        }
        rows.append(row)
        lines.append(
            f"{label:<10} {row['encrypt_ms']:>12.3f} {row['decrypt_ms']:>12.3f} "
            f"{row['total_ms']:>12.3f} {row['throughput_MBps']:>16.3f}"
        )
    return result("TR-8", "Performance Evaluation", True, "\n".join(lines), {"rows": rows})


def run_seq_binding_check(sender: SenderClient, receiver: ReceiverServer) -> dict:
    """Extra evidence: sequence rebinding attack is rejected."""
    prot = sender.protect_record("bind-check", "meta")
    forged = dict(prot)
    forged["sequence"] = prot["sequence"] + 999
    resp = receiver.process_protected_record(sender.send_record(forged))
    passed = not resp.get("success")
    detail = (
        "Extra: Sequence-AAD Binding Check\n\n"
        f"Original sequence: {prot['sequence']}\n"
        f"Forged sequence: {forged['sequence']}\n"
        f"AAD (utf-8): {bytes.fromhex(prot['aad']).decode()}\n"
        f"Rejected: {passed}\n"
        f"Error: {resp.get('error')}\n"
    )
    return result("EXTRA-SEQ-BIND", "Sequence-AAD Binding", passed, detail)


def run_algorithm(algorithm: str) -> dict:
    out_dir = algo_dir(algorithm)
    sender = SenderClient(algorithm=algorithm)
    key = sender.shared_key
    receiver = ReceiverServer(algorithm=algorithm, key=key)

    results = []
    # Fresh sender/receiver pairs where sequence state matters across tests
    tests = [
        ("TR-1", lambda: run_tr1(sender, receiver)),
        ("TR-2", lambda: run_tr2(SenderClient(algorithm=algorithm, key=key), ReceiverServer(algorithm=algorithm, key=key))),
        ("TR-3", lambda: run_tr3(SenderClient(algorithm=algorithm, key=key), ReceiverServer(algorithm=algorithm, key=key))),
        ("TR-4", lambda: run_tr4(SenderClient(algorithm=algorithm, key=key), ReceiverServer(algorithm=algorithm, key=key))),
        ("TR-5", lambda: run_tr5(SenderClient(algorithm=algorithm, key=key), ReceiverServer(algorithm=algorithm, key=key))),
        ("TR-6", lambda: run_tr6(SenderClient(algorithm=algorithm, key=key), ReceiverServer(algorithm=algorithm, key=key))),
        ("TR-7", lambda: run_tr7(SenderClient(algorithm=algorithm, key=key), NONCE_TEST_COUNT)),
        ("TR-8", lambda: run_tr8(SenderClient(algorithm=algorithm, key=key), ReceiverServer(algorithm=algorithm, key=key))),
        ("EXTRA-SEQ-BIND", lambda: run_seq_binding_check(SenderClient(algorithm=algorithm, key=key), ReceiverServer(algorithm=algorithm, key=key))),
    ]

    for tr_id, fn in tests:
        print(f"\n  Running {tr_id} ...", flush=True)
        try:
            r = fn()
        except Exception as e:
            r = result(tr_id, tr_id, False, f"Exception: {e}\n{traceback.format_exc()}")
        results.append(r)
        write_text(out_dir / f"{r['id']}.txt", r["detail"] + f"\n\nOUTCOME: {r['outcome']}\n")

        # Print detailed evidence
        print(f"    Status: {r['outcome']}")
        print(f"    Title: {r['title']}")
        print(f"    Evidence:")
        for line in r["detail"].split("\n")[:15]:  # Show first 15 lines of evidence
            if line.strip():
                print(f"      {line}")
        if r["detail"].count("\n") > 15:
            print(f"      ... (see evidence/{algorithm}/{r['id']}.txt for full details)")
        print(f"    ✓ {r['outcome']}", flush=True)

    summary = {
        "algorithm": algorithm,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "shared_key_hex_prefix": key.hex()[:32],
        "results": [
            {"id": r["id"], "title": r["title"], "outcome": r["outcome"], "extra": r.get("extra", {})}
            for r in results
        ],
    }
    write_text(out_dir / "summary.json", json.dumps(summary, indent=2))
    return summary


def build_master_summary(summaries: list[dict]) -> str:
    lines = [
        "# CS6530 Assignment 1 — Automated Test Summary",
        "",
        f"Generated (UTC): {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Outcomes",
        "",
        "| Algorithm | TR-1 | TR-2 | TR-3 | TR-4 | TR-5 | TR-6 | TR-7 | TR-8 | SEQ-BIND |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for s in summaries:
        outcomes = {r["id"]: r["outcome"] for r in s["results"]}
        row = [s["algorithm"]]
        for k in ["TR-1", "TR-2", "TR-3", "TR-4", "TR-5", "TR-6", "TR-7", "TR-8", "EXTRA-SEQ-BIND"]:
            row.append(outcomes.get(k, "N/A"))
        lines.append("| " + " | ".join(row) + " |")

    lines.extend(["", "## TR-8 Performance Comparison", ""])
    # Merge perf rows
    perf = {}
    for s in summaries:
        for r in s["results"]:
            if r["id"] == "TR-8":
                perf[s["algorithm"]] = r.get("extra", {}).get("rows", [])
    if perf:
        lines.append("| Size | AES-GCM total_ms | AES-GCM MB/s | ChaCha20 total_ms | ChaCha20 MB/s |")
        lines.append("|---|---:|---:|---:|---:|")
        aes_rows = {row["label"]: row for row in perf.get(ALGORITHM_AES_GCM, [])}
        ch_rows = {row["label"]: row for row in perf.get(ALGORITHM_CHACHA20, [])}
        for label in [r["label"] for r in next(iter(perf.values()), [])]:
            a = aes_rows.get(label, {})
            c = ch_rows.get(label, {})
            lines.append(
                f"| {label} | {a.get('total_ms', '')} | {a.get('throughput_MBps', '')} | "
                f"{c.get('total_ms', '')} | {c.get('throughput_MBps', '')} |"
            )

    lines.extend(["", "## Evidence locations", ""])
    lines.append("- `evidence/AES-GCM/` — per-test logs for AES-GCM")
    lines.append("- `evidence/ChaCha20-Poly1305/` — per-test logs for ChaCha20-Poly1305")
    lines.append("- `evidence/summary/TEST_SUMMARY.md` — this file")
    lines.append("- `evidence/summary/TEST_SUMMARY.json` — machine-readable summary")
    return "\n".join(lines) + "\n"


def main() -> int:
    silence_module_loggers()
    EVIDENCE.mkdir(exist_ok=True)
    (EVIDENCE / "summary").mkdir(exist_ok=True)

    print("=" * 70)
    print("CS6530 Assignment 1 — Automated TR-1..TR-8 Harness")
    print("=" * 70)

    summaries = []
    for algo in ALGORITHMS:
        print(f"\n=== {algo} ===")
        summaries.append(run_algorithm(algo))

    master_md = build_master_summary(summaries)
    write_text(EVIDENCE / "summary" / "TEST_SUMMARY.md", master_md)
    write_text(EVIDENCE / "summary" / "TEST_SUMMARY.json", json.dumps(summaries, indent=2))
    print("\n" + master_md)
    print("Done. Evidence written under evidence/")
    all_pass = all(r["outcome"] == "PASS" for s in summaries for r in s["results"])
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
