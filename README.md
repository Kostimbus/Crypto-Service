# Crypto Service - Secure Signing & Encryption Microservice

## A production-ready FastAPI-based cryptography microservice implementing:
- Ed25519 digital signatures (sign/verify)
- ChaCha20-Poly1305 AEAD encryption (encrypt/decrypt)
- Key rotation support with externally mounted secret keys
- Strict type checking with mypy, ruff, bandit, semgrep, pytest
- Full CI/CD pipeline using GitHub Actions, including:
    - static analysis (SAST)
    - tests
    - Docker multi-stage build
    - push to GHCR


## Used algorithms

| Serivce  | Algortihm          |
|----------|--------------------|
| Signature| Ed25519            |
| AEAD     | ChaCha20-Poly1305  |

### Envelope format
JSON fields

    {
        "v": 1,
        "alg": "CHACHA20-POLY1305",
        "kid": "k1",
        "nonce": "<base64>",
        "aad": "<base64>",
        "ct": "<base64>"
    }



# Setup 

## Python environment
    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements-dev.txt

## System tools
- Install gitleaks separately (not a Python package)
    - Linux: sudo apt install gitleaks
    - macOS: brew install gitleaks
    - Windows: choco install gitleaks
