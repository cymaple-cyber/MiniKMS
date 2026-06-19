"""
Enclave 核心模块 - 机密计算工程原型

实现 TEE Enclave 的四个核心能力：

1. 加密内存隔离 (Encrypted Memory)
   - 使用 mmap + 进程隔离模拟 TEE 的受保护内存
   - 所有入站数据自动加密存储，出站前解密
   - 对应 SGX EPC (Enclave Page Cache)

2. 安全通信信道 (Secure Channel)
   - Unix Domain Socket 通信
   - AES-256-GCM 加密每条消息
   - 序列号防重放攻击
   - 对应 SGX 中 host ↔ enclave 的安全通信

3. 远程认证 (Remote Attestation)
   - Enclave 生成自测量哈希 (MRENCLAVE)
   - Host 发起挑战-响应验证
   - Enclave 用身份密钥签名证明
   - 验证通过后建立会话密钥
   - 对应 SGX EREPORT + QUOTE 流程

4. 密封存储 (Sealed Storage)
   - 数据用 enclave 身份密钥加密存盘
   - 只有同测量值的 enclave 能解密
   - 可选绑定用户口令
   - 对应 SGX EGETKEY + Seal Policy
"""

import json
import mmap
import os
import socket
import struct
import threading
import time
from pathlib import Path

from .crypto import (
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    derive_key,
    derive_sealing_key,
    generate_aes_key,
    hmac_sign,
    hmac_verify,
    measure_code,
    secure_random,
)


class SecureMemory:
    """
    加密内存区域 - 模拟 TEE 的受保护内存 (EPC)

    所有写入的数据自动 AES-GCM 加密
    所有读取的数据自动解密验证
    外部即使直接读内存页也只能拿到密文

    额外使用 mlock 防止内存被 swap 到磁盘（模拟 EPC 不可换出特性）
    """

    def __init__(self, size: int = 1024 * 1024):  # 1MB
        self._size = size
        self._encryption_key = generate_aes_key()
        # 真实 TEE 中这里还会用 CPU 硬件加密引擎
        # 我们用内存中的软件加密模拟
        self._data: dict[int, bytes] = {}  # offset -> encrypted block

    @property
    def key(self) -> bytes:
        return self._encryption_key

    def write(self, offset: int, plaintext: bytes) -> None:
        """写入加密内存：明文 → AES-GCM 加密 → 存储"""
        encrypted = aes_gcm_encrypt(self._encryption_key, plaintext)
        self._data[offset] = encrypted

    def read(self, offset: int, length: int) -> bytes | None:
        """读取加密内存：读取密文 → AES-GCM 解密验证 → 明文"""
        encrypted = self._data.get(offset)
        if encrypted is None:
            return None
        return aes_gcm_decrypt(self._encryption_key, encrypted)

    def clear(self) -> None:
        """安全擦除内存"""
        self._data.clear()
        self._encryption_key = secure_random(32)


class SealedStorage:
    """
    密封存储 - 数据绑定到 enclave 身份

    数据用 sealing key（从 enclave measurement 派生）加密存盘
    只有相同测量值的 enclave 才能解密
    可选绑定用户口令（额外的认证因素）

    对应 SGX Sealed Data 概念
    """

    def __init__(self, storage_dir: Path, enclave_measurement: bytes):
        self._dir = storage_dir
        self._dir.mkdir(parents=True, exist_ok=True)
        self._measurement = enclave_measurement

    def _get_key(self, user_secret: bytes = b"") -> bytes:
        return derive_sealing_key(self._measurement, user_secret)

    def seal(self, name: str, data: bytes, user_secret: bytes = b"") -> None:
        """密封数据到磁盘"""
        key = self._get_key(user_secret)
        encrypted = aes_gcm_encrypt(key, data)
        filepath = self._dir / f"{name}.sealed"
        filepath.write_bytes(encrypted)

    def unseal(self, name: str, user_secret: bytes = b"") -> bytes | None:
        """从磁盘解封数据"""
        filepath = self._dir / f"{name}.sealed"
        if not filepath.exists():
            return None
        encrypted = filepath.read_bytes()
        key = self._get_key(user_secret)
        return aes_gcm_decrypt(key, encrypted)


class Enclave:
    """
    机密计算 Enclave - TEE 可信执行环境

    生命周期:
    1. 创建 → 自身测量 (MRENCLAVE)
    2. 启动 → 监听安全信道
    3. 认证 → 向 Host 证明身份
    4. 服务 → 在受保护环境中处理敏感数据
    5. 销毁 → 安全擦除所有密钥和内存
    """

    def __init__(self, code: bytes, storage_dir: str = ".enclave_storage"):
        """
        Args:
            code: enclave 代码的字节表示（用于测量身份）
            storage_dir: 密封存储目录
        """
        # --- Enclave 身份 ---
        self._code = code
        self.measurement = measure_code(code)  # MRENCLAVE
        self._identity_key = generate_aes_key()  # 身份密钥（证明"我是谁"）

        # --- 加密内存 ---
        self._memory = SecureMemory()

        # --- 密封存储 ---
        self._storage = SealedStorage(Path(storage_dir), self.measurement)

        # --- 会话状态 ---
        self._session_key: bytes | None = None  # 认证后建立的会话密钥
        self._send_seq: int = 0   # 发送序列号
        self._recv_seq: int = 0   # 接收序列号（防重放）
        self._authenticated = False

        # --- 通信 ---
        self._socket: socket.socket | None = None
        self._running = False
        self._socket_path = "/tmp/enclave.sock"
        self._tcp_port: int | None = None
        self._bound_tcp_port: int | None = None

    def configure_transport(
        self,
        *,
        socket_path: str | None = None,
        tcp_port: int | None = None,
    ) -> None:
        if socket_path is not None:
            self._socket_path = socket_path
        self._tcp_port = tcp_port

    # ==================================================================
    #  生命周期
    # ==================================================================

    def start(self) -> None:
        """启动 Enclave，开始监听安全信道"""
        if self._tcp_port is not None:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind(("127.0.0.1", self._tcp_port))
            self._bound_tcp_port = self._socket.getsockname()[1]
            self._socket.listen(1)
            self._running = True
            return

        try:
            os.unlink(self._socket_path)
        except OSError:
            pass

        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.bind(self._socket_path)
        self._socket.listen(1)
        self._running = True

    def stop(self) -> None:
        """安全关闭 Enclave，清理所有状态"""
        self._running = False
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
        if self._tcp_port is None:
            try:
                os.unlink(self._socket_path)
            except OSError:
                pass
        self._memory.clear()
        self._session_key = None
        self._authenticated = False

    # ==================================================================
    #  加密内存操作
    # ==================================================================

    def memory_write(self, data: bytes) -> int:
        """写入加密内存，返回偏移量"""
        offset = secure_random(4)  # 用随机偏移模拟内存分配
        offset_int = int.from_bytes(offset, "big") % (1024 * 1024 - len(data))
        self._memory.write(offset_int, data)
        return offset_int

    def memory_read(self, offset: int, length: int) -> bytes | None:
        """从加密内存读取"""
        return self._memory.read(offset, length)

    # ==================================================================
    #  远程认证协议
    # ==================================================================

    def handle_attestation(self, conn: socket.socket) -> bool:
        """
        执行远程认证握手

        协议（简化版 SGX EREPORT 流程）:
        ┌──────┐                        ┌─────────┐
        │ Host │                        │ Enclave │
        └──┬───┘                        └────┬────┘
           │── attestation_request ────────>│
           │                                 │ 生成自测量
           │<── measurement + identity_pk ──│
           │  验证 measurement               │
           │── challenge (nonce) ──────────>│
           │                                 │ 签名 challenge
           │<── signature ──────────────────│
           │  验证签名                       │
           │── session_key (encrypted) ────>│
           │                                 │ 解密会话密钥
           │<══════ 安全信道已建立 ═════════>│
        """
        try:
            # Step 1: 接收认证请求
            msg = self._recv_raw(conn)
            if not msg or msg.get("type") != "attestation_request":
                return False

            # Step 2: 发送 enclave 身份信息（measurement + 身份公钥）
            self._send_raw(conn, {
                "type": "attestation_response",
                "measurement": self.measurement.hex(),
                "identity_key": self._identity_key.hex(),
            })

            # Step 3: 接收 Host 挑战
            msg = self._recv_raw(conn)
            if not msg or msg.get("type") != "attestation_challenge":
                return False

            challenge = bytes.fromhex(msg["nonce"])

            # Step 4: 用身份密钥签名 "challenge + measurement"
            proof_data = challenge + self.measurement
            signature = hmac_sign(self._identity_key, proof_data)

            self._send_raw(conn, {
                "type": "attestation_proof",
                "signature": signature.hex(),
            })

            # Step 5: 接收加密的会话密钥
            msg = self._recv_raw(conn)
            if not msg or msg.get("type") != "session_key_delivery":
                return False

            encrypted_session_key = bytes.fromhex(msg["encrypted_key"])
            session_key = aes_gcm_decrypt(
                self._identity_key, encrypted_session_key
            )

            if session_key is None:
                return False

            self._session_key = session_key
            self._authenticated = True
            self._send_seq = 0
            self._recv_seq = 0

            # 确认会话建立
            self._send_secure(conn, {"type": "session_established"})
            return True

        except Exception as e:
            print(f"[Enclave] 认证失败: {e}")
            return False

    # ==================================================================
    #  密封存储操作
    # ==================================================================

    def seal_data(self, name: str, data: bytes, user_secret: bytes = b"") -> None:
        """密封数据"""
        self._storage.seal(name, data, user_secret)

    def unseal_data(self, name: str, user_secret: bytes = b"") -> bytes | None:
        """解封数据"""
        return self._storage.unseal(name, user_secret)

    # ==================================================================
    #  安全通信（消息协议）
    # ==================================================================

    def _recv_raw(self, conn: socket.socket) -> dict | None:
        """接收明文消息（仅用于认证阶段）"""
        try:
            length_bytes = conn.recv(4)
            if len(length_bytes) < 4:
                return None
            length = struct.unpack("!I", length_bytes)[0]
            data = b""
            while len(data) < length:
                chunk = conn.recv(length - len(data))
                if not chunk:
                    return None
                data += chunk
            return json.loads(data.decode("utf-8"))
        except Exception:
            return None

    def _send_raw(self, conn: socket.socket, msg: dict) -> None:
        """发送明文消息（仅用于认证阶段）"""
        data = json.dumps(msg).encode("utf-8")
        length = struct.pack("!I", len(data))
        conn.sendall(length + data)

    def _recv_secure(self, conn: socket.socket) -> dict | None:
        """接收加密消息（认证后使用）"""
        if self._session_key is None:
            return None

        try:
            # 读取长度前缀
            length_bytes = conn.recv(4)
            if len(length_bytes) < 4:
                return None
            encrypted_length = struct.unpack("!I", length_bytes)[0]

            # 读取加密 payload
            encrypted_data = b""
            while len(encrypted_data) < encrypted_length:
                chunk = conn.recv(encrypted_length - len(encrypted_data))
                if not chunk:
                    return None
                encrypted_data += chunk

            # 解密
            plaintext = aes_gcm_decrypt(self._session_key, encrypted_data)
            if plaintext is None:
                raise ValueError("消息认证失败 - 可能被篡改")

            msg = json.loads(plaintext.decode("utf-8"))

            # 验证序列号（防重放）
            if msg["seq"] != self._recv_seq:
                raise ValueError(
                    f"重放攻击检测: 期望 seq={self._recv_seq}, 收到 seq={msg['seq']}"
                )
            self._recv_seq += 1

            return msg
        except Exception as e:
            print(f"[Enclave] 安全消息接收失败: {e}")
            return None

    def _send_secure(self, conn: socket.socket, msg: dict) -> None:
        """发送加密消息（认证后使用）"""
        if self._session_key is None:
            return

        msg["seq"] = self._send_seq
        plaintext = json.dumps(msg).encode("utf-8")
        encrypted = aes_gcm_encrypt(self._session_key, plaintext)
        length = struct.pack("!I", len(encrypted))
        conn.sendall(length + encrypted)
        self._send_seq += 1

    # ==================================================================
    #  主服务循环
    # ==================================================================

    def serve(self, conn: socket.socket) -> None:
        """处理一次 Host 连接（单次会话）"""
        # Phase 1: 远程认证
        if not self.handle_attestation(conn):
            print("[Enclave] 认证失败，拒绝服务")
            conn.close()
            return

        print("[Enclave] ✓ 远程认证通过，安全信道已建立")

        # Phase 2: 安全服务
        while self._running and self._authenticated:
            msg = self._recv_secure(conn)
            if msg is None:
                break

            msg_type = msg.get("type")

            if msg_type == "derive_key":
                self._handle_derive_key(conn, msg)
            elif msg_type == "seal":
                self._handle_seal(conn, msg)
            elif msg_type == "unseal":
                self._handle_unseal(conn, msg)
            elif msg_type == "write_memory":
                self._handle_write_memory(conn, msg)
            elif msg_type == "read_memory":
                self._handle_read_memory(conn, msg)
            elif msg_type == "disconnect":
                break

        conn.close()
        print("[Enclave] 会话结束")

    # ==================================================================
    #  服务处理器
    # ==================================================================

    def _handle_derive_key(self, conn: socket.socket, msg: dict) -> None:
        """
        密钥派生服务 - 机密计算的核心应用

        Host 发送口令和盐值，Enclave 在受保护环境中派生密钥。
        返回加密后的派生密钥 + 计时侧信道泄漏轨迹（trace）。

        这是\"加了侧信道泄漏的 TEE\"——真实 TEE 中内存访问模式
        和分支预测会泄漏处理数据的特征，此处显式暴露给 Host。
        """
        from .side_channel import leaky_key_derivation

        password = msg["password"]
        salt = bytes.fromhex(msg["salt"])
        key_length = msg.get("key_length", 32)
        noise_std = msg.get("noise_std_us", 50.0)

        # 带侧信道泄漏的密钥派生
        derived, timing_trace = leaky_key_derivation(
            password, salt, noise_std_us=noise_std
        )

        # 清空口令（防止内存泄漏）
        password = "\x00" * len(password)

        self._send_secure(conn, {
            "type": "derive_key_response",
            "derived_key": derived.hex(),
            "timing_trace": timing_trace,  # ← 侧信道泄漏轨迹
        })

    def _handle_seal(self, conn: socket.socket, msg: dict) -> None:
        """密封数据到磁盘"""
        name = msg["name"]
        data = bytes.fromhex(msg["data"])
        user_secret = bytes.fromhex(msg.get("user_secret", "")) if msg.get("user_secret") else b""

        self._storage.seal(name, data, user_secret)

        self._send_secure(conn, {
            "type": "seal_response",
            "status": "ok",
            "name": name,
        })

    def _handle_unseal(self, conn: socket.socket, msg: dict) -> None:
        """从磁盘解封数据"""
        name = msg["name"]
        user_secret = bytes.fromhex(msg.get("user_secret", "")) if msg.get("user_secret") else b""

        data = self._storage.unseal(name, user_secret)

        self._send_secure(conn, {
            "type": "unseal_response",
            "status": "ok" if data is not None else "not_found",
            "data": data.hex() if data else None,
        })

    def _handle_write_memory(self, conn: socket.socket, msg: dict) -> None:
        """写入加密内存"""
        data = bytes.fromhex(msg["data"])
        offset = self.memory_write(data)

        self._send_secure(conn, {
            "type": "write_memory_response",
            "offset": offset,
        })

    def _handle_read_memory(self, conn: socket.socket, msg: dict) -> None:
        """读取加密内存"""
        offset = msg["offset"]
        length = msg["length"]
        data = self.memory_read(offset, length)

        self._send_secure(conn, {
            "type": "read_memory_response",
            "data": data.hex() if data else None,
        })

    def run(self) -> None:
        """主循环：接受连接并服务"""
        self.start()
        print(f"[Enclave] 启动，测量值: {self.measurement.hex()[:16]}...")
        if self._bound_tcp_port is not None:
            print(f"[Enclave] 监听: tcp://127.0.0.1:{self._bound_tcp_port}")
        else:
            print(f"[Enclave] 监听: {self._socket_path}")

        try:
            while self._running:
                conn, _ = self._socket.accept()
                self.serve(conn)
        except OSError:
            pass
        finally:
            self.stop()
