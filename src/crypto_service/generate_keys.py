from pathlib import Path
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


KEY_DIR = Path("keys")
KEY_DIR.mkdir(exist_ok=True)

def generate_signing_keypair(kid="k1"):
    """Generate Ed25519 signing + verification keys."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_path = KEY_DIR / f"signing_{kid}.priv"
    pub_path = KEY_DIR / f"signing_{kid}.pub"

    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    priv_path.write_bytes(priv_bytes)
    pub_path.write_bytes(pub_bytes)

    print(f"[+] Generated {priv_path} and {pub_path}")

def generate_aead_key(kid="k1"):
    """Generate 32-byte key for ChaCha20-Poly1305."""
    key_path = KEY_DIR / f"aead_{kid}.bin"
    key = os.urandom(32)
    key_path.write_bytes(key)
    print(f"[+] Generated {key_path}")

if __name__ == "__main__":
    kid = input("Enter key ID (e.g. k1): ") or "k1"
    generate_signing_keypair(kid)
    generate_aead_key(kid)
    print("\n✅ All keys generated successfully in 'keys/' folder.")
