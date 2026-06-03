# MiniKMS: A Lightweight Key Management System

MiniKMS 是一个轻量级密钥管理系统后端，用于展示密码学工程化、安全开发、权限控制、密钥生命周期管理和审计日志。第一阶段不包含前端，所有接口都可以通过 FastAPI 自带的 Swagger 文档测试。

## 技术栈

- Backend: Python, FastAPI
- ORM: SQLAlchemy 2.x
- Database: SQLite by default, PostgreSQL-ready through `DATABASE_URL`
- Auth: JWT Bearer Token
- Password Hashing: bcrypt
- Crypto: Python `cryptography`, AES-256-GCM
- Deployment: Docker, Docker Compose
- Tests: pytest, FastAPI TestClient

## 系统架构

```text
app/
├── api/          # FastAPI routers
├── models/       # SQLAlchemy ORM models
├── schemas/      # Pydantic request/response schemas
├── services/     # auth, key lifecycle, crypto, audit business logic
└── utils/        # JWT, password hashing, RBAC dependencies
```

SQLite 是本地默认数据库。后续迁移 PostgreSQL 时，核心代码不需要绑定 SQLite 特性，只需要替换 `DATABASE_URL` 并引入 Alembic 迁移即可。

## 密钥管理流程

1. Admin 或 Key Manager 调用 `POST /keys` 创建 AES-256-GCM 数据密钥。
2. 系统生成 32 字节 DEK。
3. 系统使用环境变量 `MASTER_KEY` 对 DEK 做 AES-GCM 信封加密。
4. 数据库只保存 `encrypted_key_material` 和包装 nonce，不保存明文 DEK。
5. 加密/解密数据时，系统仅在内存中临时解包 DEK。
6. `POST /keys/{key_id}/rotate` 会生成新的 DEK，将 `key_version` 递增，并保留旧版本用于历史密文解密。
7. `POST /crypto/encrypt` 返回当前 `key_version`；`POST /crypto/decrypt` 可传入 `key_version` 解密历史版本密文。
8. `disabled`、`revoked`、`destroyed` 状态的密钥不能用于加解密。
9. `DELETE /keys/{key_id}` 会将状态置为 `destroyed`，并擦除数据库中的包装后密钥材料和版本材料。

## 信封加密设计

- 数据加密算法：AES-256-GCM
- 数据密钥：每个 KMS key 一把随机 32 字节 DEK
- Master Key：从 `.env` 的 `MASTER_KEY` 读取，必须是 base64 编码的 32 字节值
- DEK 存储：使用 Master Key 包装后保存
- 数据加密：每次 `POST /crypto/encrypt` 都生成新的随机 nonce
- 密钥轮换：每个版本独立保存包装后的 DEK；API 只返回版本号，不返回密钥材料
- 错误处理：解密失败返回通用错误，不暴露内部异常或密钥材料

生成 `MASTER_KEY`：

```bash
python -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

## 角色权限

- Admin
  - 创建用户
  - 查看用户列表
  - 创建、查看、禁用、吊销、销毁密钥
  - 查看审计日志
- Key Manager
  - 创建密钥
  - 查看密钥元数据
  - 禁用、吊销、销毁密钥
- App User
  - 查看 active 状态密钥元数据
  - 使用 active 状态密钥加密/解密数据

第一个通过 `/auth/register` 注册的用户会自动成为 Admin。之后公开注册的用户默认为 App User；Admin 可通过 `POST /users` 创建指定角色的用户。

## 审计日志

审计日志字段包括：用户 ID、动作、目标类型、目标 ID、IP、User-Agent、结果、时间。

当前记录的关键动作包括：

- `login_success`
- `login_failed`
- `create_key`
- `list_key_metadata`
- `get_key_metadata`
- `encrypt`
- `decrypt`
- `rotate_key`
- `disable_key`
- `revoke_key`
- `destroy_key`
- `permission_denied`

Admin 可通过 `GET /audit/logs` 查看日志。

## 本地运行

```bash
cd 密钥管理系统
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
mkdir -p data
```

编辑 `.env`，填入强随机 `JWT_SECRET_KEY` 和 base64 32 字节 `MASTER_KEY`。

启动服务：

```bash
.venv/bin/python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

访问：

- Swagger: http://localhost:8000/docs
- OpenAPI JSON: http://localhost:8000/openapi.json
- Health: http://localhost:8000/

## Docker 运行

```bash
cd 密钥管理系统
cp .env.example .env
mkdir -p data
```

编辑 `.env` 后运行：

```bash
docker compose up --build
```

访问 Swagger：

```text
http://localhost:8000/docs
```

## Swagger 测试顺序

1. `POST /auth/register` 注册第一个用户，该用户自动成为 Admin。
2. `POST /auth/login` 登录并复制 `access_token`。
3. 点击 Swagger 右上角 `Authorize`，输入 `Bearer <access_token>`。
4. `POST /users` 创建 `key_manager` 或 `app_user`。
5. `POST /keys` 创建密钥。
6. `GET /keys` 或 `GET /keys/{key_id}` 查看密钥元数据。
7. `POST /crypto/encrypt` 使用 `key_id` 加密明文。
8. `POST /keys/{key_id}/rotate` 轮换密钥，确认返回的 `key_version` 递增。
9. `POST /crypto/decrypt` 使用返回的 `key_version`、`nonce` 和 `ciphertext` 解密。
10. `POST /keys/{key_id}/disable` 或 `POST /keys/{key_id}/revoke` 改变密钥状态。
11. `DELETE /keys/{key_id}` 销毁密钥。
12. `GET /audit/logs` 查看审计日志。

## 主要 API

### Auth

- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/me`

### Users

- `POST /users`
- `GET /users`

### Keys

- `POST /keys`
- `GET /keys`
- `GET /keys/{key_id}`
- `POST /keys/{key_id}/disable`
- `POST /keys/{key_id}/revoke`
- `POST /keys/{key_id}/rotate`
- `DELETE /keys/{key_id}`

### Crypto

- `POST /crypto/encrypt`
- `POST /crypto/decrypt`

### Audit

- `GET /audit/logs`

## 安全说明

- 密码只保存 bcrypt 哈希。
- JWT Secret 从环境变量读取。
- Master Key 从环境变量读取。
- 数据库不保存明文 DEK。
- API 响应不返回 `encrypted_key_material`、包装 nonce、DEK 明文或 Master Key。
- 密钥轮换只暴露 `key_version`，旧版本 DEK 仍以信封加密形式保存。
- disabled/revoked/destroyed 密钥不能用于加解密。
- destroyed 密钥会擦除当前版本和历史版本的包装后密钥材料。
- 权限不足会返回 403，并写入审计日志。
- 解密失败返回通用错误，避免泄露内部细节。

## 运行测试

```bash
.venv/bin/python -m pytest -q
```

## 后续可扩展方向

1. PostgreSQL 支持
2. 前端管理后台
3. 密钥审批流程
4. 自动密钥轮换策略
5. 多租户支持
6. HSM/Vault/云 KMS 对接
7. 国密算法 SM2/SM3/SM4 支持
8. 异常密钥访问检测
9. AI-assisted key misuse detection
