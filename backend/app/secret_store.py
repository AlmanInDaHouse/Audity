from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from hashlib import sha256
from secrets import token_bytes

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import get_settings


class SecretStoreError(RuntimeError):
    pass


def _build_ref(org_id: str, name: str) -> str:
    return f'secret://{org_id}/{name}'


def _parse_ref(secret_ref: str) -> tuple[str, str]:
    if not secret_ref.startswith('secret://'):
        raise SecretStoreError('Invalid secret_ref')
    raw = secret_ref[len('secret://') :]
    parts = raw.split('/', 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise SecretStoreError('Invalid secret_ref')
    return parts[0], parts[1]


@dataclass
class EnvelopeCipher:
    key_material: str

    def _key(self) -> bytes:
        return sha256(self.key_material.encode('utf-8')).digest()

    def encrypt(self, plaintext: str) -> str:
        nonce = token_bytes(12)
        aes = AESGCM(self._key())
        cipher = aes.encrypt(nonce, plaintext.encode('utf-8'), None)
        return base64.urlsafe_b64encode(nonce + cipher).decode('ascii')

    def decrypt(self, payload: str) -> str:
        raw = base64.urlsafe_b64decode(payload.encode('ascii'))
        nonce, cipher = raw[:12], raw[12:]
        aes = AESGCM(self._key())
        plain = aes.decrypt(nonce, cipher, None)
        return plain.decode('utf-8')


class SecretStore:
    async def set(self, org_id: str, name: str, value: str) -> str:
        raise NotImplementedError

    async def get(self, secret_ref: str) -> str:
        raise NotImplementedError

    async def rotate(self, secret_ref: str, new_value: str) -> str:
        org_id, name = _parse_ref(secret_ref)
        return await self.set(org_id, name, new_value)


class EnvSecretStore(SecretStore):
    _memory: dict[str, str] = {}

    def __init__(self) -> None:
        settings = get_settings()
        self.cipher = EnvelopeCipher(settings.secret_encryption_key)

    async def set(self, org_id: str, name: str, value: str) -> str:
        ref = _build_ref(org_id, name)
        self._memory[ref] = self.cipher.encrypt(value)
        return ref

    async def get(self, secret_ref: str) -> str:
        if secret_ref in os.environ:
            return os.environ[secret_ref]
        encrypted = self._memory.get(secret_ref)
        if not encrypted:
            raise SecretStoreError('Secret not found')
        return self.cipher.decrypt(encrypted)


class VaultSecretStore(SecretStore):
    def __init__(self) -> None:
        self.settings = get_settings()
        self.cipher = EnvelopeCipher(self.settings.secret_encryption_key)

    @property
    def _headers(self) -> dict[str, str]:
        return {'X-Vault-Token': self.settings.vault_token}

    async def set(self, org_id: str, name: str, value: str) -> str:
        ref = _build_ref(org_id, name)
        encrypted = self.cipher.encrypt(value)
        url = f'{self.settings.vault_addr}/v1/{self.settings.vault_mount_kv}/data/audity/{org_id}/{name}'
        payload = {'data': {'ciphertext': encrypted}}
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(url, headers=self._headers, json=payload)
        if response.status_code >= 400:
            raise SecretStoreError(f'Vault set failed: HTTP {response.status_code}')
        return ref

    async def get(self, secret_ref: str) -> str:
        org_id, name = _parse_ref(secret_ref)
        url = f'{self.settings.vault_addr}/v1/{self.settings.vault_mount_kv}/data/audity/{org_id}/{name}'
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(url, headers=self._headers)
        if response.status_code >= 400:
            raise SecretStoreError(f'Vault get failed: HTTP {response.status_code}')
        encrypted = response.json().get('data', {}).get('data', {}).get('ciphertext')
        if not encrypted:
            raise SecretStoreError('Vault secret missing ciphertext')
        return self.cipher.decrypt(encrypted)


def _build_store() -> SecretStore:
    settings = get_settings()
    if settings.secret_store_backend == 'vault':
        return VaultSecretStore()
    return EnvSecretStore()


_secret_store: SecretStore | None = None


def get_secret_store() -> SecretStore:
    global _secret_store
    if _secret_store is None:
        _secret_store = _build_store()
    return _secret_store
