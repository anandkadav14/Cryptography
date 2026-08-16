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
        prot = sender.protect_record(pt, aad)
        resp = receiver.process_protected_record(sender.send_record(prot))
        match = resp.get("success") and resp.get("plaintext") == pt
        ok = ok and match
        lines.append(f"Record {i}: plaintext={pt!r} aad={aad!r}")
        lines.append(f"  sequence={prot['sequence']} nonce={prot['nonce']}")
        lines.append(f"  success={resp.get('success')} recovered={resp.get('plaintext')!r}")
        lines.append(f"  match={match}")
        lines.append("")
    return result("TR-1", "Positive Baseline Test", ok, "\n".join(lines), {"records": len(plaintexts)})


def run_tr2(sender: SenderClient, receiver: ReceiverServer) -> dict:
    prot = sender.protect_record("integrity-plaintext", "aad-tr2")
    tampered = sender.create_tampered_ciphertext(prot)
    resp = receiver.process_protected_record(sender.send_record(tampered))
    passed = (not resp.get("success"))
    detail = (
        "TR-2 Ciphertext Integrity Test\n\n"
        f"Original ciphertext: {prot['ciphertext']}\n"
        f"Tampered ciphertext: {tampered['ciphertext']}\n"
        f"Receiver success: {resp.get('success')}\n"
        f"Error: {resp.get('error')}\n"
        f"Plaintext released: {resp.get('plaintext')}\n"
    )
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
    prot = sender.protect_record("replay-plaintext", "aad-tr5")
    js = sender.send_record(prot)
    r1 = receiver.process_protected_record(js)
    r2 = receiver.process_protected_record(js)
    passed = bool(r1.get("success")) and (not r2.get("success")) and bool(r2.get("replay"))
    detail = (
        "TR-5 Replay Test\n\n"
        f"Sequence: {prot['sequence']}\n"
        f"1st attempt success: {r1.get('success')} plaintext={r1.get('plaintext')!r}\n"
        f"2nd attempt success: {r2.get('success')} replay={r2.get('replay')} error={r2.get('error')}\n"
    )
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
    nonces = set()
    reuse_at = None
    t0 = time.perf_counter()
    for i in range(count):
        prot = sender.protect_record(f"nonce-test-{i}", f"seq-meta:{i}")
        n = prot["nonce"]
        if n in nonces:
            reuse_at = i
            break
        nonces.add(n)
    elapsed = time.perf_counter() - t0
    passed = reuse_at is None and len(nonces) == count
    detail = (
        "TR-7 Nonce Management Verification\n\n"
        f"Records requested: {count}\n"
        f"Unique nonces: {len(nonces)}\n"
        f"Reuse detected at index: {reuse_at}\n"
        f"Elapsed seconds: {elapsed:.4f}\n"
        f"Sample first nonce: {next(iter(nonces)) if nonces else 'n/a'}\n"
        f"Sample last nonce: {prot['nonce'] if passed else 'n/a'}\n"
    )
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
        print(f"  Running {tr_id} ...", flush=True)
        try:
            r = fn()
        except Exception as e:
            r = result(tr_id, tr_id, False, f"Exception: {e}\n{traceback.format_exc()}")
        results.append(r)
        write_text(out_dir / f"{r['id']}.txt", r["detail"] + f"\n\nOUTCOME: {r['outcome']}\n")
        print(f"    -> {r['outcome']}", flush=True)

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
