#!/bin/bash

# Test Suite Runner for Secure Data Protection Subsystem
# Runs all 8 testing requirements for both AES-GCM and ChaCha20-Poly1305

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=============================================================="
echo "Secure Data Protection Subsystem - Test Suite"
echo "=============================================================="
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python3 not found"
    exit 1
fi

echo "Python: $(python3 --version)"

# Check dependencies
echo ""
echo "Checking dependencies..."
python3 -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305" 2>/dev/null || {
    echo "❌ cryptography library not found"
    echo "Installing dependencies..."
    pip install -r requirements.txt
}

echo "✓ All dependencies satisfied"

# Run tests
echo ""
echo "=============================================================="
echo "Running Tests..."
echo "=============================================================="
echo ""

python3 client/test_harness.py

echo ""
echo "=============================================================="
echo "Test Suite Complete"
echo "=============================================================="
