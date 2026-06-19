"""
KMS Enclave - 可信 KMS 的 TEE 侧

Master Key 仅存在于 Enclave 进程内，Host（MiniKMS）通过安全信道请求：
  - 生成并包装 DEK
  - 在 Enclave 内完成数据加解密（DEK 不离开 Enclave）
"""

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import measure_code, secure_random
from .enclave import Enclave

ENCLAVE_CODE = b"trusted-kms-enclave-v1.0"
DEFAULT_SOCKET_PATH = "/tmp/trusted-kms-enclave.sock"
DEK_ASSOCIATED_DATA = b"minikms-dek-v1"


def load_master_key_from_env() -> bytes:
    encoded = os.environ["MASTER_KEY"].encode("ascii")
    encoded += b"=" * (-len(encoded) % 4)
    raw = base64.urlsafe_b64decode(encoded)
    if len(raw) != 32:
        raise ValueError("MASTER_KEY must decode to exactly 32 bytes")
    return raw


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _b64decode(encoded: str) -> bytes:
    value = encoded.encode("ascii")
    value += b"=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value)


class KmsEnclave(Enclave):
    """扩展 Enclave，提供 MiniKMS 所需的密钥包装与数据加解密服务。"""

    def __init__(
        self,
        code: bytes,
        master_key: bytes,
        *,
        socket_path: str = DEFAULT_SOCKET_PATH,
        tcp_port: int | None = None,
        storage_dir: str = ".kms_enclave_storage",
    ):
        super().__init__(code, storage_dir=storage_dir)
        self.configure_transport(socket_path=socket_path, tcp_port=tcp_port)
        self._master_key = master_key
        self._master_aesgcm = AESGCM(master_key)

    def _wrap_dek(self, dek: bytes) -> tuple[str, str]:
        nonce = secure_random(12)
        ciphertext = self._master_aesgcm.encrypt(nonce, dek, DEK_ASSOCIATED_DATA)
        return _b64encode(ciphertext), _b64encode(nonce)

    def _unwrap_dek(self, encrypted_key_material: str, nonce: str) -> bytes:
        enc = _b64decode(encrypted_key_material)
        nonce_bytes = _b64decode(nonce)
        try:
            return self._master_aesgcm.decrypt(nonce_bytes, enc, DEK_ASSOCIATED_DATA)
        except (InvalidTag, ValueError) as exc:
            raise ValueError("Key material cannot be used") from exc

    def serve(self, conn) -> None:
        if not self.handle_attestation(conn):
            print("[KmsEnclave] 认证失败，拒绝服务")
            conn.close()
            return

        print("[KmsEnclave] ✓ 远程认证通过，KMS 服务就绪")

        while self._running and self._authenticated:
            msg = self._recv_secure(conn)
            if msg is None:
                break

            msg_type = msg.get("type")
            if msg_type == "kms_generate_wrapped_dek":
                self._handle_generate_wrapped_dek(conn)
            elif msg_type == "kms_encrypt":
                self._handle_encrypt(conn, msg)
            elif msg_type == "kms_decrypt":
                self._handle_decrypt(conn, msg)
            elif msg_type == "disconnect":
                break
            else:
                self._send_secure(conn, {"type": "error", "detail": f"unknown type: {msg_type}"})

        conn.close()
        print("[KmsEnclave] 会话结束")

    def _handle_generate_wrapped_dek(self, conn) -> None:
        dek = secure_random(32)
        encrypted_key_material, nonce = self._wrap_dek(dek)
        dek = b"\x00" * 32
        self._send_secure(
            conn,
            {
                "type": "kms_generate_wrapped_dek_response",
                "encrypted_key_material": encrypted_key_material,
                "nonce": nonce,
            },
        )

    def _handle_encrypt(self, conn, msg: dict) -> None:
        try:
            dek = self._unwrap_dek(msg["encrypted_key_material"], msg["key_nonce"])
            data_nonce = secure_random(12)
            ciphertext = AESGCM(dek).encrypt(
                data_nonce,
                msg["plaintext"].encode("utf-8"),
                msg["key_id"].encode("utf-8"),
            )
            dek = b"\x00" * 32
            self._send_secure(
                conn,
                {
                    "type": "kms_encrypt_response",
                    "nonce": _b64encode(data_nonce),
                    "ciphertext": _b64encode(ciphertext),
                },
            )
        except ValueError:
            self._send_secure(conn, {"type": "error", "detail": "Key material cannot be used"})

    def _handle_decrypt(self, conn, msg: dict) -> None:
        try:
            dek = self._unwrap_dek(msg["encrypted_key_material"], msg["key_nonce"])
            nonce_bytes = _b64decode(msg["nonce"])
            ciphertext = _b64decode(msg["ciphertext"])
            plaintext = AESGCM(dek).decrypt(
                nonce_bytes,
                ciphertext,
                msg["key_id"].encode("utf-8"),
            )
            dek = b"\x00" * 32
            self._send_secure(
                conn,
                {
                    "type": "kms_decrypt_response",
                    "plaintext": plaintext.decode("utf-8"),
                },
            )
        except (InvalidTag, ValueError):
            self._send_secure(conn, {"type": "error", "detail": "Decryption failed"})


def expected_measurement() -> bytes:
    return measure_code(ENCLAVE_CODE)


def run_kms_enclave() -> None:
    master_key = load_master_key_from_env()
    socket_path = os.environ.get("ENCLAVE_SOCKET_PATH", DEFAULT_SOCKET_PATH)
    tcp_port = int(os.environ["ENCLAVE_PORT"]) if os.environ.get("ENCLAVE_PORT") else None
    enclave = KmsEnclave(
        ENCLAVE_CODE,
        master_key,
        socket_path=socket_path,
        tcp_port=tcp_port,
    )
    enclave.run()


if __name__ == "__main__":
    run_kms_enclave()
