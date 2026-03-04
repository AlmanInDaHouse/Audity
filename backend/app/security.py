from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import InvalidTokenError
from pydantic import BaseModel

from app.config import get_settings


class TokenClaims(BaseModel):
    sub: str
    email: str
    org_id: str
    role: str
    iss: str
    exp: int


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


class OIDCSigner:
    def __init__(self) -> None:
        settings = get_settings()
        self.kid = settings.oidc_key_id
        private_key_b64 = settings.oidc_private_key_b64.strip()
        if private_key_b64:
            private_bytes = base64.b64decode(private_key_b64)
            self.private_key = serialization.load_pem_private_key(private_bytes, password=None)
        else:
            # why this: local mock OIDC must work without external IdP or pre-generated key material.
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def token(self, *, sub: str, email: str, org_id: str, role: str) -> str:
        settings = get_settings()
        exp = datetime.now(UTC) + timedelta(hours=8)
        payload = {
            'sub': sub,
            'email': email,
            'org_id': org_id,
            'role': role,
            'iss': settings.oidc_issuer,
            'exp': int(exp.timestamp()),
        }
        return jwt.encode(payload, self.private_pem, algorithm='RS256', headers={'kid': self.kid})

    @property
    def private_pem(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def public_pem(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def jwks(self) -> dict[str, Any]:
        numbers = self.public_key.public_numbers()
        n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')
        e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big')
        return {
            'keys': [
                {
                    'kty': 'RSA',
                    'use': 'sig',
                    'kid': self.kid,
                    'alg': 'RS256',
                    'n': _b64url(n),
                    'e': _burl(e),
                }
            ]
        }

    def decode(self, token: str) -> TokenClaims:
        settings = get_settings()
        try:
            payload = jwt.decode(token, self.public_pem, algorithms=['RS256'], issuer=settings.oidc_issuer)
        except InvalidTokenError as exc:
            raise ValueError(str(exc)) from exc
        return TokenClaims.model_validate(payload)


def _burl(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


@lru_cache(maxsize=1)
def get_signer() -> OIDCSigner:
    return OIDCSigner()


def jwks_json() -> str:
    return json.dumps(get_signer().jwks())
