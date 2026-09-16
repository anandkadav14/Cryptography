"""Generate long-term Ed25519 identity keys for Alice and Bob."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from config import KEYS_DIR
from crypto.identity import export_public_key_copy, generate_identity_keypair


def main() -> None:
    alice_dir = KEYS_DIR / "alice"
    bob_dir = KEYS_DIR / "bob"
    trusted = KEYS_DIR / "trusted"

    generate_identity_keypair(alice_dir)
    generate_identity_keypair(bob_dir)

    export_public_key_copy(alice_dir, trusted / "alice_ed25519_public.pem")
    export_public_key_copy(bob_dir, trusted / "bob_ed25519_public.pem")

    print("Generated identity keys:")
    print(f"  Alice private/public: {alice_dir}")
    print(f"  Bob private/public:   {bob_dir}")
    print(f"  Trusted public keys:  {trusted}")


if __name__ == "__main__":
    main()
