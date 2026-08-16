# CS6530 Assignment 1 — Automated Test Summary

Generated (UTC): 2026-08-16T11:12:22.898242+00:00

## Outcomes

| Algorithm | TR-1 | TR-2 | TR-3 | TR-4 | TR-5 | TR-6 | TR-7 | TR-8 | SEQ-BIND |
|---|---|---|---|---|---|---|---|---|---|
| AES-GCM | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| ChaCha20-Poly1305 | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |

## TR-8 Performance Comparison

| Size | AES-GCM total_ms | AES-GCM MB/s | ChaCha20 total_ms | ChaCha20 MB/s |
|---|---:|---:|---:|---:|
| 64B | 0.054 | 1.141 | 0.047 | 1.307 |
| 1KiB | 0.032 | 30.422 | 0.053 | 18.322 |
| 64KiB | 0.375 | 166.711 | 0.422 | 147.929 |

## Evidence locations

- `evidence/AES-GCM/` — per-test logs for AES-GCM
- `evidence/ChaCha20-Poly1305/` — per-test logs for ChaCha20-Poly1305
- `evidence/summary/TEST_SUMMARY.md` — this file
- `evidence/summary/TEST_SUMMARY.json` — machine-readable summary
