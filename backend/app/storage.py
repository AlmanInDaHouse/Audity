from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass

import boto3
from botocore.client import BaseClient
from botocore.exceptions import ClientError

from app.config import get_settings


@dataclass
class StoredObject:
    key: str
    sha256: str
    size: int


class MemoryObjectStore:
    _objects: dict[str, bytes] = {}

    async def ensure_bucket(self) -> None:
        return

    async def put_bytes(self, key: str, data: bytes, content_type: str) -> StoredObject:
        self._objects[key] = data
        return StoredObject(key=key, sha256=hashlib.sha256(data).hexdigest(), size=len(data))

    async def get_bytes(self, key: str) -> bytes:
        if key not in self._objects:
            raise FileNotFoundError(key)
        return self._objects[key]


class S3ObjectStore:
    def __init__(self) -> None:
        settings = get_settings()
        endpoint = settings.minio_endpoint
        if not endpoint.startswith('http'):
            endpoint = f"{'https' if settings.minio_secure else 'http'}://{endpoint}"
        self.bucket = settings.minio_bucket
        self.client: BaseClient = boto3.client(
            's3',
            endpoint_url=endpoint,
            aws_access_key_id=settings.minio_access_key,
            aws_secret_access_key=settings.minio_secret_key,
            region_name='us-east-1',
        )

    async def ensure_bucket(self) -> None:
        try:
            self.client.head_bucket(Bucket=self.bucket)
        except ClientError:
            self.client.create_bucket(Bucket=self.bucket)

    async def put_bytes(self, key: str, data: bytes, content_type: str) -> StoredObject:
        self.client.upload_fileobj(io.BytesIO(data), self.bucket, key, ExtraArgs={'ContentType': content_type})
        return StoredObject(key=key, sha256=hashlib.sha256(data).hexdigest(), size=len(data))

    async def get_bytes(self, key: str) -> bytes:
        with io.BytesIO() as output:
            self.client.download_fileobj(self.bucket, key, output)
            return output.getvalue()


def get_object_store() -> MemoryObjectStore | S3ObjectStore:
    settings = get_settings()
    if settings.storage_backend == 's3':
        return S3ObjectStore()
    return MemoryObjectStore()
