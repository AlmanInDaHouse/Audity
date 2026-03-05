from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.config import get_settings
from app.secret_store import SecretStoreError, get_secret_store


def _signing_ref(org_id: str) -> str:
    return f'secret://{org_id}/signing_key_ed25519'


async def _load_or_create_private_key(org_id: str) -> Ed25519PrivateKey:
    store = get_secret_store()
    ref = _signing_ref(org_id)
    try:
        pem = await store.get(ref)
        return serialization.load_pem_private_key(pem.encode('utf-8'), password=None)
    except SecretStoreError:
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode('utf-8')
        await store.set(org_id, 'signing_key_ed25519', pem)
        return key


def _tsa_token(manifest_hash: str) -> str:
    settings = get_settings()
    if settings.tsa_provider == 'external' and settings.tsa_url:
        # why this: external TSA client is intentionally abstracted to avoid coupling MVP runtime to a single vendor.
        return f'external:{manifest_hash}'
    issued = datetime.now(UTC).isoformat()
    return f'stub:{issued}:{manifest_hash[:16]}'


async def sign_manifest(org_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    private_key = await _load_or_create_private_key(org_id)
    canonical = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')
    digest = hashlib.sha256(canonical).hexdigest()
    signature = private_key.sign(canonical)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        'manifest': payload,
        'manifest_sha256': digest,
        'signature': base64.b64encode(signature).decode('ascii'),
        'public_key': base64.b64encode(public_key).decode('ascii'),
        'timestamp_token': _tsa_token(digest),
        'signed_at': datetime.now(UTC).isoformat(),
    }


def verify_bundle(bundle: dict[str, Any]) -> bool:
    manifest = bundle.get('manifest')
    signature_b64 = bundle.get('signature')
    public_key_b64 = bundle.get('public_key')
    if not isinstance(manifest, dict) or not isinstance(signature_b64, str) or not isinstance(public_key_b64, str):
        return False
    canonical = json.dumps(manifest, separators=(',', ':'), sort_keys=True).encode('utf-8')
    signature = base64.b64decode(signature_b64.encode('ascii'))
    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64.encode('ascii')))
    try:
        public_key.verify(signature, canonical)
    except Exception:
        return False
    digest = hashlib.sha256(canonical).hexdigest()
    return digest == bundle.get('manifest_sha256')
