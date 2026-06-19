# 可信 KMS（Trusted KMS）设计说明

## 1. 系统架构

```text
┌─────────────────────────────────────────────────────────────┐
│  Client / Swagger                                           │
└───────────────────────────┬─────────────────────────────────┘
                            │ HTTPS / JWT
┌───────────────────────────▼─────────────────────────────────┐
│  MiniKMS Host（不可信）                                       │
│  - 用户鉴权、RBAC、审计日志                                   │
│  - 密钥元数据（DB 仅存包装后的 DEK）                          │
│  - 不含 Master Key，不解包 DEK                                │
└───────────────────────────┬─────────────────────────────────┘
                            │ Unix Socket + 远程认证 + AES-GCM 信道
┌───────────────────────────▼─────────────────────────────────┐
│  KmsEnclave（可信区，模拟 TEE）                               │
│  - 持有 Master Key                                           │
│  - 生成 / 包装 DEK                                           │
│  - 解包 DEK 并执行 AES-GCM 数据加解密                         │
│  - 明文 DEK 不出 Enclave                                      │
└─────────────────────────────────────────────────────────────┘
```

## 2. 密钥层次

| 层级 | 名称 | 存放位置 | 用途 |
|------|------|----------|------|
| L0 | Master Key | 仅 Enclave 进程 | 包装 / 解包 DEK |
| L1 | DEK（数据加密密钥） | DB 中为密文（包装后） | 加密业务明文 |
| L2 | 业务明文 | 应用侧 | 用户数据 |

**信封加密：**

```text
Master Key  ──wrap──▶  DEK  ──AES-GCM──▶  业务密文
                ↑              ↑
           只在 Enclave     包装后的 DEK 存 DB
```

## 3. 协议流程

### 3.1 启动

1. 启动 `KmsEnclave`，从环境变量加载 `MASTER_KEY`
2. 启动 MiniKMS，`USE_ENCLAVE=true`，Host **不**配置 `MASTER_KEY`
3. MiniKMS 启动时与 Enclave 完成远程认证，建立会话密钥

### 3.2 创建密钥

1. Host 调用 Enclave：`kms_generate_wrapped_dek`
2. Enclave 生成随机 DEK，用 Master Key 包装
3. Host 将 `encrypted_key_material` + `nonce` 写入数据库

### 3.3 加密 / 解密

1. Host 从 DB 读取包装后的 DEK 与元数据
2. Host 将密文请求转发给 Enclave（不传明文 DEK）
3. Enclave 内部解包 DEK → AES-GCM 加解密 → 返回结果
4. Host 写审计日志

## 4. 威胁模型

### 防护目标

| 威胁 | 缓解 |
|------|------|
| 数据库泄露 | DB 无 Master Key、无明文 DEK |
| Host 进程被攻破 | 攻击者拿不到 Master Key；加解密需通过已认证 Enclave |
| 篡改 Enclave 通信 | AES-GCM 会话加密 + 序列号防重放 |
| 冒充 Enclave | 远程认证（measurement + 挑战-响应签名） |

### 明确不防护

| 场景 | 说明 |
|------|------|
| 物理攻击 | 软件模拟 TEE，非 SGX 硬件 |
| Enclave 进程被攻破 | 模拟环境下 Enclave 仍是普通进程 |
| 合法管理员双端控制 | 同时控制 Host 与 Enclave 仍可解密 |
| 侧信道 | 未做 timing / 内存访问防护 |

## 5. 与纯 MiniKMS 对比

| 项目 | MiniKMS（本地模式） | Trusted KMS |
|------|---------------------|-------------|
| Master Key 位置 | Host `.env` | 仅 Enclave |
| DEK 解包 | Host 内存 | Enclave 内存 |
| 远程认证 | 无 | 有 |
| 适用场景 | 开发 / 单机 | 演示可信密钥托管 |

## 6. 运行方式

见 `密钥管理系统/README.md` 中 **Trusted KMS 模式** 一节。
