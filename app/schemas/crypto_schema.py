from pydantic import BaseModel, Field


class EncryptRequest(BaseModel):
    key_id: str
    plaintext: str = Field(min_length=1)


class EncryptResponse(BaseModel):
    key_id: str
    key_version: int
    nonce: str
    ciphertext: str


class DecryptRequest(BaseModel):
    key_id: str
    key_version: int | None = Field(default=None, ge=1)
    nonce: str
    ciphertext: str


class DecryptResponse(BaseModel):
    plaintext: str
