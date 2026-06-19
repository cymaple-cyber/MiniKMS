# Claude Code 交接文档 — 可信 KMS（Trusted KMS）

> 最后更新：2026-06-18  
> 读者：Claude Code / 后续 AI Agent / 接手开发者

---

## 1. 项目是什么

这是一个 **应用密码学方向的毕设/申研项目**，主线是：

**可信 KMS = MiniKMS（密钥管理 API）+ 模拟 TEE Enclave（敏感密码操作）**

用户（Owner）已 **放弃 CLRM 侧信道研究**，不再写入申研/论文材料。当前叙事是：

> 面向模拟可信执行环境的轻量级密钥管理系统设计与实现

---

## 2. 目录结构（重要）

```text
MiniKMS/                          # GitHub repo root (github.com/cymaple-cyber/MiniKMS)
├── app/                          # Host API
├── enclave/                      # Simulated TEE (in-repo, was ../机密计算)
├── start-trusted-kms.sh          # One-click launcher
├── docs/
│   ├── TRUSTED_KMS.md
│   ├── 论文大纲.md
│   └── CLAUDE_CODE_HANDOFF.md
└── tests/
```

**Note:** Enclave code is vendored under `enclave/` so a single `git clone` is enough for GitHub users.

---

## 3. 当前完成状态

### 已完成

| 功能 | 状态 |
|------|------|
| MiniKMS 后端（JWT/RBAC/审计/轮换） | ✅ |
| 信封加密 AES-256-GCM | ✅ |
| Trusted KMS（Enclave 后端） | ✅ |
| 远程认证 + 会话加密信道 | ✅ |
| Enclave 内 DEK 包装/解包/加解密 | ✅ |
| 一键启动脚本 | ✅ |
| 集成测试 8 passed | ✅ |
| 论文大纲 | ✅ `docs/论文大纲.md` |
| 设计文档 | ✅ `docs/TRUSTED_KMS.md` |

### 未完成 / 可扩展

| 项 | 说明 |
|----|------|
| 论文章节正文 | 只有大纲，未写初稿 |
| 前端管理界面 | 仅 Swagger |
| PostgreSQL / Alembic | 仍用 SQLite |
| 真实 SGX/Nitro | 仍是软件模拟 |
| PQC（ML-KEM） | 未做 |
| Docker 双容器部署 | 有 Dockerfile 但未拆 Enclave 容器 |
| 使用说明独立 md | 目前在 README 中 |

---

## 4. 一键启动（给用户/demo 用）

```bash
cd MiniKMS   # repo root after git clone
./start-trusted-kms.sh
# or: bash start-trusted-kms.sh
```

- 自动从 `密钥管理系统/.env` 读取 `MASTER_KEY`（**只给 Enclave**）
- API 默认 http://127.0.0.1:8000/docs
- 健康检查：`GET /` → `"crypto_backend":"enclave"`, `"enclave":"connected"`
- `Ctrl+C` 停止 Enclave + API

可选：`API_PORT=8001 ENCLAVE_PORT=9788 ./start-trusted-kms.sh`

---

## 5. 开发验证命令

```bash
cd "/Users/cyjiang/Desktop/学习/项目/20_安全应用与实验/密钥管理系统"

# 全部测试（8 项）
.venv/bin/python -m pytest -q

# 仅可信模式
.venv/bin/python -m pytest tests/test_trusted_kms.py -q

# 仅本地模式
.venv/bin/python -m pytest tests/test_minikms_api.py -q
```

**上次结果：** 8 passed

---

## 6. 架构要点（写论文/改代码必知）

### 6.1 两种运行模式

| 模式 | 环境变量 | Master Key 位置 | DEK 解包 |
|------|----------|-----------------|----------|
| 本地 | `USE_ENCLAVE=false` | Host `.env` | Host 内存 |
| 可信 | `USE_ENCLAVE=true` | 仅 Enclave 进程 | Enclave 内存 |

`config.py` 在 `USE_ENCLAVE=true` 时会 **忽略** Host `.env` 中的 `MASTER_KEY`。

### 6.2 Enclave 通信

- 默认 TCP：`ENCLAVE_PORT=9787`（一键脚本）
- 也支持 Unix Socket：`ENCLAVE_SOCKET_PATH=/tmp/trusted-kms-enclave.sock`
- 协议：先远程认证（明文），后 AES-GCM 加密消息 + seq 防重放

### 6.3 Enclave KMS 消息

| type | 方向 | 作用 |
|------|------|------|
| `kms_generate_wrapped_dek` | Host→Enclave | 创建密钥时生成包装 DEK |
| `kms_encrypt` | Host→Enclave | 加密明文 |
| `kms_decrypt` | Host→Enclave | 解密密文 |

实现见：`机密计算/src/kms_enclave.py`、`密钥管理系统/app/services/enclave_client.py`

### 6.4 密钥/crypto 约定

- DEK 包装 AAD：`b"minikms-dek-v1"`
- 数据加密 AAD：`key_id.encode()`
- Enclave 代码测量常量：`b"trusted-kms-enclave-v1.0"`

---

## 7. 安全红线（Agent 必须遵守）

**禁止：**

- 在日志、回复、commit message 中打印 `MASTER_KEY`、DEK、`encrypted_key_material`
- 在 API 响应中返回密钥材料
- 把 `.env` 内容提交到 Git
- 在论文中夸大成「硬件 SGX 级隔离」或「生产级 KMS」
- 重新引入 CLRM 侧信道作为本文主线（用户已放弃）

**修改 crypto / enclave 协议时：**

- 必须同步更新 `tests/test_trusted_kms.py`
- 必须同步更新 `docs/TRUSTED_KMS.md`
- Host 与 Enclave 的 AAD、消息 type 必须一致

---

## 8. 论文写作任务（优先给 Claude Code 的工作）

论文大纲已导出：`docs/论文大纲.md`

**推荐 Claude Code 执行顺序：**

1. **第 3 章 威胁模型** — 基于 `TRUSTED_KMS.md` 扩写
2. **第 4 章 总体设计** — 画架构图、密钥层次图（可用 Mermaid）
3. **第 5 章 协议实现** — 远程认证时序图 + KMS 消息说明
4. **第 6 章 系统实现** — 引用实际文件路径与启动方式
5. **第 7 章 测试** — 引用 pytest 用例与结果
6. **第 2 章 文献** — 补 KMS、TEE、AEAD 引用
7. **第 1 章 + 摘要 + 第 8 章**

**输出建议目录（可新建）：**

```text
docs/thesis/
├── ch01-绪论.md
├── ch02-相关技术.md
├── ...
└── figures/          # 架构图、时序图
```

**图表优先产出：**

- 图 4-1 系统架构
- 图 4-2 密钥层次
- 图 5-1 远程认证时序
- 图 5-2 加解密时序
- 表 4-1 API 权限矩阵
- 表 7-1 测试用例

---

## 9. 代码修改建议（若继续开发）

按优先级：

| 优先级 | 任务 | 价值 |
|--------|------|------|
| P0 | 撰写论文章节初稿 | 申研/毕设直接产出 |
| P1 | 导出架构图/时序图 PNG | 论文插图 |
| P2 | 性能对比实验（local vs enclave） | 第 7 章加分 |
| P3 | 简易 Web 前端 | 演示 |
| P4 | ML-KEM 混合封装 | 密码学深度 |

**不要做大重构**，当前架构已够写论文。

---

## 10. 常见问题排查

| 现象 | 处理 |
|------|------|
| `enclave: disconnected` | 先启动 Enclave，或用 `./start-trusted-kms.sh` |
| 端口 8000 占用 | `API_PORT=8001 ./start-trusted-kms.sh` |
| `PermissionError` bind socket | 在系统终端跑，别在受限沙箱；或用 TCP 模式 |
| 测试 `crypto_backend: local` | 确认 `USE_ENCLAVE=true` 且 Host 无有效 MASTER_KEY 校验冲突；跑前 `get_settings.cache_clear()` |
| 机密计算 import 失败 | 确认 `机密计算/venv` 存在且装了 `cryptography` |

---

## 11. 关键文件速查

| 目的 | 文件 |
|------|------|
| 改 API | `app/api/*.py` |
| 改密钥逻辑 | `app/services/key_service.py` |
| 改加解密路由 | `app/services/crypto_service.py` |
| 改 Enclave 客户端 | `app/services/enclave_client.py` |
| 改 Enclave 服务端 | `../机密计算/src/kms_enclave.py` |
| 改配置 | `app/config.py` |
| 改启动 | `../start-trusted-kms.sh` |
| 写论文 | `docs/论文大纲.md` |
| 理解设计 | `docs/TRUSTED_KMS.md` |

---

## 12. 给 Claude Code 的启动 Prompt 模板

复制以下段落作为新会话第一条消息：

```markdown
请阅读以下交接文档并开始工作：

/Users/cyjiang/Desktop/学习/项目/20_安全应用与实验/密钥管理系统/docs/CLAUDE_CODE_HANDOFF.md
/Users/cyjiang/Desktop/学习/项目/20_安全应用与实验/密钥管理系统/docs/论文大纲.md
/Users/cyjiang/Desktop/学习/项目/20_安全应用与实验/密钥管理系统/docs/TRUSTED_KMS.md

任务：按论文大纲撰写第 3 章（威胁模型）和第 4 章（总体设计）初稿，
输出到 docs/thesis/ 目录。基于现有代码，不要虚构未实现的功能。
边界：模拟 TEE，非硬件 SGX，非生产级 KMS。
```

---

## 13. 交接结论

- **代码侧：** 可信 KMS 已可运行、可测试、可一键 demo，无需从零搭建。
- **文档侧：** 设计说明 + 论文大纲已就绪，缺的是 **章节正文与插图**。
- **下一任 Agent 首选任务：** 按 `docs/论文大纲.md` 写论文，而非加新功能。

旧版 MiniKMS 交接见项目根目录 `NEXT_AGENT_HANDOFF.md`（内容偏 Phase 1 本地模式，已部分过时；以本文件为准）。
