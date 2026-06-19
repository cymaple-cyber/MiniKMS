# Trusted KMS

A lightweight **Key Management System** with an optional **simulated TEE Enclave** backend.

Master Key and DEK unwrapping stay inside the Enclave process; the Host API never holds the Master Key in trusted mode.

## Features

- AES-256-GCM envelope encryption (Master Key → DEK → data)
- Key lifecycle: create, rotate, disable, revoke, destroy
- JWT auth, RBAC (Admin / Key Manager / App User), audit logs
- **Trusted mode:** remote attestation + encrypted Host↔Enclave channel
- One-command startup, Swagger UI, pytest suite (8 tests)

## Quick Start

```bash
git clone https://github.com/cymaple-cyber/MiniKMS.git
cd MiniKMS

python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

cp .env.example .env
# Edit .env: set JWT_SECRET_KEY and MASTER_KEY (see below)

chmod +x start-trusted-kms.sh
./start-trusted-kms.sh
```

Open **http://127.0.0.1:8000/docs**

Health check: `GET /` should return `"crypto_backend": "enclave"`.

Generate keys:

```bash
python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

## Project Layout

```text
app/                  # FastAPI Host (MiniKMS API)
enclave/              # Simulated TEE + KMS crypto handlers
docs/                 # Design docs, thesis outline
start-trusted-kms.sh  # One-click launcher
tests/
```

## Modes

| Mode | `USE_ENCLAVE` | Master Key location |
|------|---------------|---------------------|
| Local | `false` (default) | Host `.env` |
| Trusted | `true` | Enclave process only |

Trusted mode: copy `.env.trusted.example` or set `USE_ENCLAVE=true` and **do not** pass `MASTER_KEY` to the Host process (the startup script handles this).

## Manual Start (two terminals)

**Terminal 1 — Enclave**

```bash
export MASTER_KEY="<base64-32-byte-key>"
export ENCLAVE_PORT=9787
.venv/bin/python -m enclave.kms_enclave
```

**Terminal 2 — API**

```bash
export USE_ENCLAVE=true
export ENCLAVE_PORT=9787
export JWT_SECRET_KEY="<secret>"
unset MASTER_KEY
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## Tests

```bash
.venv/bin/python -m pytest -q
```

## Documentation

| Doc | Description |
|-----|-------------|
| [docs/TRUSTED_KMS.md](docs/TRUSTED_KMS.md) | Architecture & threat model |
| [docs/论文大纲.md](docs/论文大纲.md) | Thesis outline (Chinese) |
| [docs/CLAUDE_CODE_HANDOFF.md](docs/CLAUDE_CODE_HANDOFF.md) | Developer handoff |

## Security Notes

This is an **educational / prototype** system:

- Simulated TEE, not hardware SGX
- Not production-grade KMS
- Do not commit `.env` or real secrets

## License

MIT — see [LICENSE](LICENSE).

## Citation / 中文简介

**面向模拟可信执行环境的轻量级密钥管理系统**：在 Host 不可信的威胁模型下，将 Master Key 与 DEK 敏感操作隔离至 Enclave，实现信封加密、远程认证与密钥生命周期管理。
