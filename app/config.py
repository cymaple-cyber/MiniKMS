import base64
from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Trusted KMS: Enclave-backed Key Management System"
    database_url: str = "sqlite:///./minikms.db"
    jwt_secret_key: str = Field(min_length=16)
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    master_key: str | None = None
    use_enclave: bool = False
    enclave_socket_path: str = "/tmp/trusted-kms-enclave.sock"
    enclave_port: int | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @model_validator(mode="after")
    def validate_crypto_mode(self) -> "Settings":
        if self.use_enclave:
            # Host 进程忽略 .env 中可能残留的 MASTER_KEY，真实 Master Key 只在 Enclave 内。
            object.__setattr__(self, "master_key", None)
        elif not self.master_key:
            raise ValueError("MASTER_KEY is required when USE_ENCLAVE=false")
        return self

    def master_key_bytes(self) -> bytes:
        if not self.master_key:
            raise ValueError("MASTER_KEY is not configured on this host")
        encoded = self.master_key.encode("ascii")
        encoded += b"=" * (-len(encoded) % 4)
        raw = base64.urlsafe_b64decode(encoded)
        if len(raw) != 32:
            raise ValueError("MASTER_KEY must decode to exactly 32 bytes")
        return raw


@lru_cache
def get_settings() -> Settings:
    return Settings()
