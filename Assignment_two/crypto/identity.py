"""Long-term Ed25519 identity key handling."""

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _key_paths(role_dir: Path) -> tuple[Path, Path]:
    return role_dir / "ed25519_private.pem", role_dir / "ed25519_public.pem"


def generate_identity_keypair(role_dir: Path) -> None:
    role_dir.mkdir(parents=True, exist_ok=True)
    priv_path, pub_path = _key_paths(role_dir)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    pub_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def load_private_key(role_dir: Path) -> Ed25519PrivateKey:
    priv_path, _ = _key_paths(role_dir)
    return serialization.load_pem_private_key(priv_path.read_bytes(), password=None)


def load_public_key(path: Path) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(path.read_bytes())


def export_public_key_copy(source_role_dir: Path, trusted_path: Path) -> None:
    _, pub_path = _key_paths(source_role_dir)
    trusted_path.parent.mkdir(parents=True, exist_ok=True)
    trusted_path.write_bytes(pub_path.read_bytes())


def fingerprint_public_key(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()[:16]


def save_session_archive(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
