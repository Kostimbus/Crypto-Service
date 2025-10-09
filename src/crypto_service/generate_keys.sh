#!/usr/bin/env bash
set -euo pipefail

mkdir -p keys
KID="${1:-k1}"

echo "[*] Generating Ed25519 signing keypair..."
python - <<PY
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from pathlib import Path
sk = Ed25519PrivateKey.generate()
pk = sk.public_key()
priv = Path("keys/signing_${KID}.priv")
pub  = Path("keys/signing_${KID}.pub")
priv.write_bytes(sk.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()))
pub.write_bytes(pk.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw))
print(f"Wrote {priv} and {pub}")
PY

echo "[*] Generating AEAD key..."
python - <<PY
import os, pathlib
pathlib.Path("keys").mkdir(exist_ok=True)
path = f"keys/aead_${KID}.bin"
open(path, "wb").write(os.urandom(32))
print(f"Wrote {path}")
PY

echo "✅ All keys generated successfully (key ID: ${KID})"
