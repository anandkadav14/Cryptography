"""
Interactive CLI for Secure Data Protection Subsystem
Allows users to manually test AES-GCM and ChaCha20-Poly1305
"""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from client.client import SenderClient
from server.server import ReceiverServer
from shared.config import ALGORITHM_AES_GCM, ALGORITHM_CHACHA20, NONCE_TEST_COUNT
from shared.crypto_engine import AuthenticationError


class SecureDataProtectionCLI:
    """Interactive CLI for testing secure data protection subsystem"""

    def __init__(self):
        self.algorithm = None
        self.sender = None
        self.receiver = None
        self.running = True

    def clear_screen(self):
        """Clear terminal screen"""
        os.system('clear' if os.name != 'nt' else 'cls')

    def print_header(self, title):
        """Print section header"""
        print(f"\n{'='*70}")
        print(f"  {title}")
        print(f"{'='*70}\n")

    def select_algorithm(self):
        """Let user select AEAD algorithm"""
        self.print_header("SELECT ALGORITHM")

        print("Choose AEAD Algorithm:")
        print("  1. AES-GCM")
        print("  2. ChaCha20-Poly1305")
        print()

        choice = input("Enter choice (1 or 2): ").strip()

        if choice == "1":
            self.algorithm = ALGORITHM_AES_GCM
            print(f"\n✓ Selected: {ALGORITHM_AES_GCM}")
        elif choice == "2":
            self.algorithm = ALGORITHM_CHACHA20
            print(f"\n✓ Selected: {ALGORITHM_CHACHA20}")
        else:
            print("✗ Invalid choice")
            return False

        # Initialize sender and receiver with selected algorithm
        self.sender = SenderClient(algorithm=self.algorithm)
        key_hex = self.sender.get_shared_key_hex()
        key_bytes = bytes.fromhex(key_hex)
        self.receiver = ReceiverServer(algorithm=self.algorithm, key=key_bytes)

        # Store full key for later reference
        self.shared_key_hex = key_hex

        print(f"✓ Sender and Receiver initialized with shared key")
        print(f"✓ Shared Key: {key_hex[:32]}...")
        print(f"\n💡 Tip: Use menu option to view full key for TR-6 custom key testing\n")

        return True

    def encrypt_record(self):
        """Let user encrypt a plaintext record"""
        if not self.sender:
            print("✗ Please select an algorithm first")
            return

        self.print_header("ENCRYPT RECORD (SENDER)")

        # Get plaintext from user
        plaintext = input("Enter plaintext to encrypt: ").strip()
        if not plaintext:
            print("✗ Plaintext cannot be empty")
            return

        # Get optional AAD
        aad_input = input("Enter Associated Data (AAD) [optional, press Enter to skip]: ").strip()
        aad = aad_input if aad_input else None

        try:
            # Encrypt
            protected = self.sender.protect_record(plaintext, aad)
            json_record = self.sender.send_record(protected)

            print(f"\n✓ Record encrypted successfully!")
            print(f"\nProtected Record Details:")
            print(f"  Sequence:    {protected['sequence']}")
            print(f"  Nonce:       {protected['nonce'][:20]}...")
            print(f"  Ciphertext:  {protected['ciphertext'][:40]}...")
            print(f"  Tag:         {protected['tag']}")
            print(f"  AAD:         {protected['aad'] if protected['aad'] else '(none)'}")
            print(f"  Algorithm:   {protected['algorithm']}")

            print(f"\nFull Protected Record (JSON):")
            print(json.dumps(protected, indent=2))

            # Save for later use
            self.last_protected_record = protected
            self.last_json_record = json_record
            self.last_plaintext = plaintext

        except Exception as e:
            print(f"✗ Encryption failed: {str(e)}")

    def decrypt_record(self):
        """Let user decrypt a protected record"""
        if not self.receiver:
            print("✗ Please select an algorithm first")
            return

        self.print_header("DECRYPT RECORD (RECEIVER)")

        # Ask if user wants to use last record or paste new one
        if hasattr(self, 'last_json_record'):
            print("Use last encrypted record? (y/n): ", end='')
            use_last = input().strip().lower() == 'y'
        else:
            use_last = False

        if use_last:
            json_record = self.last_json_record
            print("✓ Using last encrypted record\n")
        else:
            print("Paste protected record JSON (multiline input, end with empty line):")
            lines = []
            while True:
                line = input()
                if not line:
                    break
                lines.append(line)
            json_record = '\n'.join(lines)

        try:
            response = self.receiver.process_protected_record(json_record)

            if response['success']:
                print(f"\n✓ Record decrypted successfully!")
                print(f"\nDecrypted Details:")
                print(f"  Plaintext: {response['plaintext']}")
                print(f"  Sequence:  {response['sequence']}")
                print(f"  Algorithm: {response['algorithm']}")
                print(f"  AAD valid: ✓")

                # Verify if it matches original
                if hasattr(self, 'last_plaintext') and response['plaintext'] == self.last_plaintext:
                    print(f"\n✓ Plaintext matches original!")

            else:
                print(f"\n✗ Decryption failed!")
                print(f"  Error: {response['error']}")
                print(f"  Reason: {response.get('message', 'Authentication failed')}")

        except Exception as e:
            print(f"✗ Decryption error: {str(e)}")

    def tamper_record(self):
        """Let user tamper with a record (Malicious Actor)"""
        if not hasattr(self, 'last_protected_record'):
            print("✗ No record to tamper. Encrypt a record first.")
            return

        self.print_header("TAMPER WITH RECORD (MALICIOUS ACTOR)")

        print("Tamper options:")
        print("  1. Tamper ciphertext")
        print("  2. Tamper authentication tag")
        print("  3. Tamper AAD")
        print("  4. Replay (send same record twice)")
        print()

        choice = input("Enter choice (1-4): ").strip()

        if choice == "1":
            print("\n→ Tampering with ciphertext...")
            tampered = self.sender.create_tampered_ciphertext(self.last_protected_record)
            print(f"✓ Ciphertext tampered!")
            print(f"  Original:  {self.last_protected_record['ciphertext'][:40]}...")
            print(f"  Tampered:  {tampered['ciphertext'][:40]}...")

            # Try to decrypt
            print(f"\n→ Attempting to decrypt tampered record...")
            json_tampered = self.sender.send_record(tampered)
            response = self.receiver.process_protected_record(json_tampered)

            if not response['success']:
                print(f"✓ DETECTED! Record rejected: {response['error']}")
            else:
                print(f"✗ ERROR: Tampered record was accepted!")

        elif choice == "2":
            print("\n→ Tampering with authentication tag...")
            tampered = self.sender.create_tampered_tag(self.last_protected_record)
            print(f"✓ Tag tampered!")
            print(f"  Original:  {self.last_protected_record['tag']}")
            print(f"  Tampered:  {tampered['tag']}")

            # Try to decrypt
            print(f"\n→ Attempting to decrypt tampered record...")
            json_tampered = self.sender.send_record(tampered)
            response = self.receiver.process_protected_record(json_tampered)

            if not response['success']:
                print(f"✓ DETECTED! Record rejected: {response['error']}")
            else:
                print(f"✗ ERROR: Tampered record was accepted!")

        elif choice == "3":
            print("\n→ Tampering with AAD...")
            tampered = self.sender.create_tampered_aad(self.last_protected_record)
            print(f"✓ AAD tampered!")
            print(f"  Original:  {self.last_protected_record['aad']}")
            print(f"  Tampered:  {tampered['aad']}")

            # Try to decrypt
            print(f"\n→ Attempting to decrypt with tampered AAD...")
            json_tampered = self.sender.send_record(tampered)
            response = self.receiver.process_protected_record(json_tampered)

            if not response['success']:
                print(f"✓ DETECTED! Record rejected: {response['error']}")
            else:
                print(f"✗ ERROR: Tampered record was accepted!")

        elif choice == "4":
            print("\n→ Replaying record (sending same record twice)...")
            print(f"  Sequence: {self.last_protected_record['sequence']}")

            # First time (should succeed)
            print(f"\n1st attempt (original):")
            response1 = self.receiver.process_protected_record(self.last_json_record)
            if response1['success']:
                print(f"  ✓ Accepted (first time)")
            else:
                print(f"  ✗ Rejected: {response1['error']}")

            # Second time (should fail due to replay)
            print(f"\n2nd attempt (replay of same record):")
            response2 = self.receiver.process_protected_record(self.last_json_record)
            if not response2['success'] and response2.get('replay'):
                print(f"  ✓ DETECTED as replay! Message: {response2['error']}")
            else:
                print(f"  ✗ ERROR: Replay was not detected!")

        else:
            print("✗ Invalid choice")

    def test_wrong_key(self):
        """Test decryption with wrong key or correct key"""
        if not hasattr(self, 'last_protected_record'):
            print("✗ No record to test. Encrypt a record first.")
            return

        self.print_header("TEST: WRONG KEY (TR-6)")

        print("\nKey Testing Options:")
        print("  1. Test with CORRECT key (should succeed)")
        print("  2. Test with WRONG key (auto-generated)")
        print("  3. Test with CUSTOM key (paste your own hex key)")
        choice = input("\nEnter choice (1-3): ").strip()

        # Extract record details
        nonce = bytes.fromhex(self.last_protected_record['nonce'])
        ciphertext = bytes.fromhex(self.last_protected_record['ciphertext'])
        tag = bytes.fromhex(self.last_protected_record['tag'])
        aad = bytes.fromhex(self.last_protected_record['aad']) if self.last_protected_record['aad'] else b''

        from shared.crypto_engine import CryptoEngine
        import os

        if choice == "1":
            # Test with CORRECT key
            print("\nTesting with CORRECT key...")
            test_key = self.sender.shared_key
            test_engine = CryptoEngine(self.algorithm, test_key)
            try:
                plaintext = test_engine.decrypt(ciphertext, tag, nonce, aad)
                print("✓ PASSED! Decryption with CORRECT key succeeded")
                print(f"  Plaintext recovered: {plaintext.decode('utf-8', errors='ignore')[:50]}...")
            except AuthenticationError:
                print("✗ FAILED! Decryption with correct key failed (should have succeeded)")

        elif choice == "2":
            # Test with WRONG key (auto-generated)
            print("\nTesting with WRONG key (auto-generated)...")
            wrong_key = os.urandom(32)
            test_engine = CryptoEngine(self.algorithm, wrong_key)
            try:
                test_engine.decrypt(ciphertext, tag, nonce, aad)
                print("✗ FAILED! Decryption with wrong key succeeded (should have failed)")
            except AuthenticationError:
                print("✓ PASSED! Decryption with WRONG key correctly failed")
                print("  Error: Authentication verification failed")

        elif choice == "3":
            # Test with CUSTOM key (user pastes)
            print("\nPaste custom key (hex format, 64 characters for 256-bit key):")
            custom_key_hex = input().strip()
            try:
                custom_key = bytes.fromhex(custom_key_hex)
                if len(custom_key) != 32:
                    print(f"✗ Invalid key size: expected 32 bytes, got {len(custom_key)}")
                    return
                test_engine = CryptoEngine(self.algorithm, custom_key)
                plaintext = test_engine.decrypt(ciphertext, tag, nonce, aad)
                print("✓ PASSED! Decryption with custom key succeeded")
                print(f"  Plaintext recovered: {plaintext.decode('utf-8', errors='ignore')[:50]}...")
            except ValueError:
                print("✗ Invalid hex format. Please paste a valid hex string.")
            except AuthenticationError:
                print("✓ Custom key failed to decrypt (authentication error)")
                print("  This is expected if the custom key is different from the correct key")
        else:
            print("✗ Invalid choice")

    def test_nonce_uniqueness(self):
        """Test nonce uniqueness (TR-7)"""
        if not self.sender:
            print("✗ Please select an algorithm first")
            return

        self.print_header("TEST: NONCE UNIQUENESS (TR-7)")

        count = int(input(f"How many records to test? (default {NONCE_TEST_COUNT}): ") or str(NONCE_TEST_COUNT))

        print(f"\nGenerating {count} records and checking for nonce uniqueness...\n")

        nonces = set()
        plaintext = "Test record"

        for i in range(count):
            protected = self.sender.protect_record(f"{plaintext} {i}", f"seq:{i}")
            nonce = protected['nonce']

            if nonce in nonces:
                print(f"✗ FAILED! Nonce reuse detected at record {i}")
                return

            nonces.add(nonce)

            if (i + 1) % 20 == 0:
                print(f"  ✓ {i + 1} records generated, all nonces unique")

        print(f"\n✓ PASSED! Generated {len(nonces)} records with all unique nonces")
        print(f"  Total: {len(nonces)} unique nonces")

    def performance_test(self):
        """Test performance of encryption/decryption (TR-8)"""
        if not self.sender or not self.receiver:
            print("✗ Please select an algorithm first")
            return

        self.print_header("TEST: PERFORMANCE EVALUATION (TR-8)")

        import time

        sizes = [64, 1024, 65536]  # 64B, 1KB, 64KB

        print(f"Testing performance with {self.algorithm}\n")
        print(f"{'Size':<12} {'Encrypt (ms)':<15} {'Decrypt (ms)':<15} {'Total (ms)':<12} {'Throughput':<12}")
        print("-" * 70)

        for size in sizes:
            plaintext = "X" * size
            aad = "metadata"

            # Encryption
            start = time.time()
            protected = self.sender.protect_record(plaintext, aad)
            encrypt_ms = (time.time() - start) * 1000

            # Decryption
            json_record = self.sender.send_record(protected)
            start = time.time()
            response = self.receiver.process_protected_record(json_record)
            decrypt_ms = (time.time() - start) * 1000

            total_ms = encrypt_ms + decrypt_ms
            throughput = (size / (total_ms / 1000)) / 1024 / 1024  # MB/s

            size_str = f"{size}B" if size < 1024 else f"{size // 1024}KB"
            print(f"{size_str:<12} {encrypt_ms:<15.3f} {decrypt_ms:<15.3f} {total_ms:<12.3f} {throughput:<12.2f} MB/s")

    def show_shared_key(self):
        """Display the full shared key in hex format"""
        if not self.algorithm or not hasattr(self, 'shared_key_hex'):
            print("✗ Please select an algorithm first")
            return

        self.print_header("VIEW SHARED KEY")
        print(f"Algorithm: {self.algorithm}\n")
        print(f"Shared Key (hex format - 64 characters):")
        print(f"\n{self.shared_key_hex}\n")
        print("Use this key for TR-6 custom key testing (paste the full 64-char hex string)")

    def show_menu(self):
        """Display main menu"""
        self.print_header("SECURE DATA PROTECTION SUBSYSTEM")

        if self.algorithm:
            print(f"Current Algorithm: {self.algorithm}\n")

        print("Menu Options:")
        print("  1. Select/Change Algorithm")
        print("  2. Encrypt Record (Sender)")
        print("  3. Decrypt Record (Receiver)")
        print("  4. Tamper with Record (Malicious Actor)")
        print("  5. Test: Wrong Key (TR-6)")
        print("  6. Test: Nonce Uniqueness (TR-7)")
        print("  7. Test: Performance Evaluation (TR-8)")
        print("  8. View Shared Key (for TR-6 testing)")
        print("  9. Exit")
        print()

    def run(self):
        """Run the CLI application"""
        print("\n" + "=" * 70)
        print("  Welcome to Secure Data Protection Subsystem")
        print("  CS6530 - Applied Cryptography - Assignment 1")
        print("=" * 70)
        print("\nSelect an algorithm to begin.\n")

        while self.running:
            self.show_menu()
            choice = input("Enter choice (1-9): ").strip()

            if choice == "1":
                self.select_algorithm()
            elif choice == "2":
                self.encrypt_record()
            elif choice == "3":
                self.decrypt_record()
            elif choice == "4":
                self.tamper_record()
            elif choice == "5":
                self.test_wrong_key()
            elif choice == "6":
                self.test_nonce_uniqueness()
            elif choice == "7":
                self.performance_test()
            elif choice == "8":
                self.show_shared_key()
            elif choice == "9":
                print("\n✓ Thank you for using the Secure Data Protection Subsystem")
                self.running = False
            else:
                print("✗ Invalid choice")

            if self.running:
                input("\nPress Enter to continue...")


if __name__ == "__main__":
    cli = SecureDataProtectionCLI()
    cli.run()
