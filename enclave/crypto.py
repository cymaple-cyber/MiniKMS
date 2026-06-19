"""
密码学原语模块 - 机密计算工程原型

封装所有底层密码操作：
  - AES-256-GCM 认证加密（安全通信信道）
  - PBKDF2 密钥派生（模拟 Enclave 内密钥派生服务）
  - 安全随机数生成
  - 密封密钥派生（enclave identity → sealing key）
"""

import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


# --- 常量 ---
AES_KEY_SIZE = 32       # AES-256
GCM_NONCE_SIZE = 12     # 96-bit nonce
GCM_TAG_SIZE = 16       # 128-bit authentication tag
PBKDF2_ITERATIONS = 600_000  # OWASP 推荐


# --- 安全随机数 ---

def secure_random(size: int) -> bytes:
    """生成密码学安全的随机字节"""
    return os.urandom(size)


def generate_aes_key() -> bytes:
    """生成 AES-256 密钥"""
    return AESGCM.generate_key(bit_length=256)


# --- AES-256-GCM 加密 ---

def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """
    AES-256-GCM 加密 + 认证
    
    返回: nonce(12B) + ciphertext + tag(16B)
    GCM 模式提供 AEAD: 同时保证机密性和完整性
    """
    nonce = secure_random(GCM_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    # ciphertext 已包含 16 字节 tag
    return nonce + ciphertext


def aes_gcm_decrypt(key: bytes, encrypted_data: bytes, associated_data: bytes = b"") -> bytes | None:
    """
    AES-256-GCM 解密 + 认证验证
    
    输入: nonce(12B) + ciphertext_with_tag
    如果 tag 验证失败（数据被篡改），返回 None
    """
    if len(encrypted_data) < GCM_NONCE_SIZE + GCM_TAG_SIZE:
        return None

    nonce = encrypted_data[:GCM_NONCE_SIZE]
    ciphertext = encrypted_data[GCM_NONCE_SIZE:]

    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    except Exception:
        return None  # 认证失败


# --- 密钥派生（模拟 Enclave 内 KDF 服务） ---

def derive_key(password: str, salt: bytes, key_length: int = 32) -> bytes:
    """
    从口令派生密钥 - PBKDF2-HMAC-SHA256
    
    实际 TEE 场景中可能用 Argon2id，这里用 PBKDF2 概念一致
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


# --- Enclave 身份测量 ---

def measure_code(code_bytes: bytes) -> bytes:
    """
    对 enclave 代码做测量哈希
    
    对应真实 SGX 中的 MRENCLAVE（Enclave Measurement）
    Host 用这个值验证它正在和正确的 enclave 通信
    """
    return hashlib.sha256(code_bytes).digest()


# --- 密封密钥 ---

def derive_sealing_key(enclave_measurement: bytes, secret: bytes = b"") -> bytes:
    """
    从 enclave 测量值派生密封密钥
    
    只有相同测量值的 enclave 才能解密被密封的数据
    对应 SGX 中的 EGETKEY + Seal Policy (MRENCLAVE)
    
    secret: 可选附加密钥材料（如用户口令），进一步绑定密封
    """
    material = enclave_measurement + secret
    return hashlib.sha256(b"sealing-key-v1:" + material).digest()


# --- HMAC 签名 ---

def hmac_sign(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA256 签名"""
    return hmac.new(key, message, hashlib.sha256).digest()


def hmac_verify(key: bytes, message: bytes, signature: bytes) -> bool:
    """验证 HMAC-SHA256 签名"""
    expected = hmac_sign(key, message)
    return hmac.compare_digest(expected, signature)
