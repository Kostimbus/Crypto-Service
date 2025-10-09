# src/crypto_service/api.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from .crypto import Signer, AEAD
from .crypto import b64d, b64e
from .keys import load_ed25519_pair, load_aead_key


app = FastAPI(title="Crypto Service")

# Load keys from env (simple single-active-key demo)
SIGN_KID = os.getenv("ACTIVE_SIGNING_KID", "k1")
AEAD_KID = os.getenv("ACTIVE_AEAD_KID", "k1")
SK_PATH = os.getenv("SIGNING_KEY_PATH", "keys/signing_k1.priv")
PK_PATH = os.getenv("VERIFY_KEY_PATH",  "keys/signing_k1.pub")
AEAD_PATH = os.getenv("AEAD_KEY_PATH",  "keys/aead_k1.bin")

sk, pk = load_ed25519_pair(SK_PATH, PK_PATH)
aead_key = load_aead_key(AEAD_PATH)
signer = Signer(sk, pk, SIGN_KID)
aead = AEAD(aead_key, AEAD_KID)


class Msg(BaseModel):
    data: str  # base64

class Signed(BaseModel):
    data: str
    sig: str

class Envelope(BaseModel):
    v: int; alg: str; kid: str; nonce: str; aad: str; ct: str


@app.post("/sign")
def sign(m: Msg):
    return signer.sign(b64d(m.data))

@app.post("/verify")
def verify(s: Signed):
    ok = signer.verify(b64d(s.data), s.sig)
    return {"valid": ok}

@app.post("/encrypt")
def encrypt(m: Msg):
    env = aead.encrypt(b64d(m.data), aad=b"ctx:v1")
    return env

@app.post("/decrypt")
def decrypt(env: Envelope):
    try:
        pt = aead.decrypt(env.dict())
        return {"data": b64e(pt)}
    except Exception:
        raise HTTPException(status_code=400, detail="decryption failed")
