"""
Enclave KMS Client - MiniKMS Host 侧与 TEE Enclave 通信

Host 通过 Unix Domain Socket 与 KmsEnclave 交互：
  1. 远程认证，建立安全信道
  2. 请求 DEK 生成/包装与数据加解密（明文 DEK 不进入 Host 内存）
"""

from __future__ import annotations

import json
import socket
import struct
import threading
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException, status

from app.config import get_settings

# 与 机密计算/src/kms_enclave.py 保持一致
ENCLAVE_CODE = b"trusted-kms-enclave-v1.0"


def _measure_code(code_bytes: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(code_bytes).digest()


def _secure_random(size: int) -> bytes:
    import os

    return os.urandom(size)


def _aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    nonce = _secure_random(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext


def _aes_gcm_decrypt(key: bytes, encrypted_data: bytes, associated_data: bytes = b"") -> bytes | None:
    if len(encrypted_data) < 28:
        return None
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    except Exception:
        return None


def _hmac_sign(key: bytes, message: bytes) -> bytes:
    import hashlib
    import hmac as hmac_lib

    return hmac_lib.new(key, message, hashlib.sha256).digest()


def _hmac_verify(key: bytes, message: bytes, signature: bytes) -> bool:
    import hmac as hmac_lib

    expected = _hmac_sign(key, message)
    return hmac_lib.compare_digest(expected, signature)


class EnclaveKmsClient:
    def __init__(
        self,
        *,
        socket_path: str,
        enclave_port: int | None,
        expected_measurement: bytes,
    ):
        self._socket_path = socket_path
        self._enclave_port = enclave_port
        self._expected_measurement = expected_measurement
        self._session_key: bytes | None = None
        self._send_seq = 0
        self._recv_seq = 0
        self._socket: socket.socket | None = None
        self._lock = threading.Lock()

    @property
    def is_connected(self) -> bool:
        return self._socket is not None and self._session_key is not None

    def connect_and_attest(self) -> None:
        with self._lock:
            self._disconnect_unlocked()
            self._connect_and_attest_unlocked()

    def disconnect(self) -> None:
        with self._lock:
            self._disconnect_unlocked()

    def _disconnect_unlocked(self) -> None:
        if self._socket and self._session_key:
            try:
                self._send_secure_unlocked({"type": "disconnect"})
            except Exception:
                pass
        if self._socket:
            self._socket.close()
        self._socket = None
        self._session_key = None
        self._send_seq = 0
        self._recv_seq = 0

    def generate_wrapped_dek(self) -> tuple[str, str]:
        response = self._request({"type": "kms_generate_wrapped_dek"})
        self._ensure_ok(response, "kms_generate_wrapped_dek_response")
        return response["encrypted_key_material"], response["nonce"]

    def encrypt_data(
        self,
        *,
        key_id: str,
        encrypted_key_material: str,
        key_nonce: str,
        plaintext: str,
    ) -> tuple[str, str]:
        response = self._request(
            {
                "type": "kms_encrypt",
                "key_id": key_id,
                "encrypted_key_material": encrypted_key_material,
                "key_nonce": key_nonce,
                "plaintext": plaintext,
            }
        )
        self._ensure_ok(response, "kms_encrypt_response")
        return response["nonce"], response["ciphertext"]

    def decrypt_data(
        self,
        *,
        key_id: str,
        encrypted_key_material: str,
        key_nonce: str,
        nonce: str,
        ciphertext: str,
    ) -> str:
        response = self._request(
            {
                "type": "kms_decrypt",
                "key_id": key_id,
                "encrypted_key_material": encrypted_key_material,
                "key_nonce": key_nonce,
                "nonce": nonce,
                "ciphertext": ciphertext,
            }
        )
        self._ensure_ok(response, "kms_decrypt_response")
        return response["plaintext"]

    def _request(self, msg: dict) -> dict:
        with self._lock:
            if not self.is_connected:
                self._connect_and_attest_unlocked()
            self._send_secure_unlocked(msg)
            response = self._recv_secure_unlocked()
            if response is None:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Enclave did not respond",
                )
            if response.get("type") == "error":
                detail = response.get("detail", "Enclave operation failed")
                code = (
                    status.HTTP_400_BAD_REQUEST
                    if "Decryption" in detail or "Key material" in detail
                    else status.HTTP_503_SERVICE_UNAVAILABLE
                )
                raise HTTPException(status_code=code, detail=detail)
            return response

    @staticmethod
    def _ensure_ok(response: dict, expected_type: str) -> None:
        if response.get("type") != expected_type:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Unexpected enclave response",
            )

    def _connect_and_attest_unlocked(self) -> None:
        try:
            self._socket = socket.socket(socket.AF_INET if self._enclave_port else socket.AF_UNIX, socket.SOCK_STREAM)
            if self._enclave_port:
                self._socket.connect(("127.0.0.1", self._enclave_port))
            else:
                self._socket.connect(self._socket_path)
        except FileNotFoundError as exc:
            self._socket = None
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Enclave is not running. Start it with: python -m enclave.kms_enclave",
            ) from exc
        except OSError as exc:
            self._socket = None
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Enclave is not running or not reachable",
            ) from exc

        self._send_raw({"type": "attestation_request"})
        msg = self._recv_raw()
        if not msg or msg.get("type") != "attestation_response":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Enclave attestation failed",
            )

        measurement = bytes.fromhex(msg["measurement"])
        identity_key = bytes.fromhex(msg["identity_key"])
        if measurement != self._expected_measurement:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Enclave measurement mismatch",
            )

        challenge = _secure_random(32)
        self._send_raw({"type": "attestation_challenge", "nonce": challenge.hex()})
        msg = self._recv_raw()
        if not msg or msg.get("type") != "attestation_proof":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Enclave attestation proof missing",
            )

        signature = bytes.fromhex(msg["signature"])
        if not _hmac_verify(identity_key, challenge + measurement, signature):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Enclave attestation signature invalid",
            )

        self._session_key = _secure_random(32)
        encrypted_key = _aes_gcm_encrypt(identity_key, self._session_key)
        self._send_raw({"type": "session_key_delivery", "encrypted_key": encrypted_key.hex()})
        msg = self._recv_secure_unlocked()
        if not msg or msg.get("type") != "session_established":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Enclave session not established",
            )

    def _send_raw(self, msg: dict) -> None:
        assert self._socket is not None
        data = json.dumps(msg).encode("utf-8")
        self._socket.sendall(struct.pack("!I", len(data)) + data)

    def _recv_raw(self) -> dict | None:
        assert self._socket is not None
        length_bytes = self._recv_exact(4)
        if length_bytes is None:
            return None
        length = struct.unpack("!I", length_bytes)[0]
        data = self._recv_exact(length)
        if data is None:
            return None
        return json.loads(data.decode("utf-8"))

    def _send_secure_unlocked(self, msg: dict) -> None:
        assert self._socket is not None and self._session_key is not None
        msg["seq"] = self._send_seq
        encrypted = _aes_gcm_encrypt(self._session_key, json.dumps(msg).encode("utf-8"))
        self._socket.sendall(struct.pack("!I", len(encrypted)) + encrypted)
        self._send_seq += 1

    def _recv_secure_unlocked(self) -> dict | None:
        assert self._socket is not None and self._session_key is not None
        length_bytes = self._recv_exact(4)
        if length_bytes is None:
            return None
        length = struct.unpack("!I", length_bytes)[0]
        encrypted = self._recv_exact(length)
        if encrypted is None:
            return None
        plaintext = _aes_gcm_decrypt(self._session_key, encrypted)
        if plaintext is None:
            return None
        msg = json.loads(plaintext.decode("utf-8"))
        if msg["seq"] != self._recv_seq:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Enclave replay detected",
            )
        self._recv_seq += 1
        return msg

    def _recv_exact(self, length: int) -> bytes | None:
        assert self._socket is not None
        chunks: list[bytes] = []
        remaining = length
        while remaining > 0:
            chunk = self._socket.recv(remaining)
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)


_client: EnclaveKmsClient | None = None


def get_enclave_client() -> EnclaveKmsClient:
    global _client
    if _client is None:
        settings = get_settings()
        _client = EnclaveKmsClient(
            socket_path=settings.enclave_socket_path,
            enclave_port=settings.enclave_port,
            expected_measurement=_measure_code(ENCLAVE_CODE),
        )
    return _client


def reset_enclave_client() -> None:
    global _client
    if _client is not None:
        _client.disconnect()
    _client = None
