import base64
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "MiniKMS: A Lightweight Key Management System"
    database_url: str = "sqlite:///./minikms.db"
    jwt_secret_key: str = Field(min_length=16)
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    master_key: str = Field(min_length=32)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    def master_key_bytes(self) -> bytes:
        encoded = self.master_key.encode("ascii")
        encoded += b"=" * (-len(encoded) % 4)
        raw = base64.urlsafe_b64decode(encoded)
        if len(raw) != 32:
            raise ValueError("MASTER_KEY must decode to exactly 32 bytes")
        return raw


@lru_cache
def get_settings() -> Settings:
    return Settings()

