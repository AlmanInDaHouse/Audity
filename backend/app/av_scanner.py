from __future__ import annotations

import socket

from app.config import get_settings


def _clamd_instream_frame(data: bytes) -> bytes:
    parts = []
    chunk_size = 1024 * 16
    for i in range(0, len(data), chunk_size):
        chunk = data[i : i + chunk_size]
        parts.append(len(chunk).to_bytes(4, 'big') + chunk)
    parts.append((0).to_bytes(4, 'big'))
    return b''.join(parts)


async def scan_upload_activity(content: bytes) -> str:
    settings = get_settings()
    if not settings.feature_upload_av_scan and not settings.enterprise_features_enabled:
        return 'clean'

    try:
        with socket.create_connection(
            (settings.clamav_host, settings.clamav_port),
            timeout=settings.clamav_timeout_seconds,
        ) as sock:
            sock.sendall(b'nINSTREAM\n')
            sock.sendall(_clamd_instream_frame(content))
            result = sock.recv(4096).decode('utf-8', errors='ignore').strip()
    except Exception:
        return 'scan_error'

    if 'FOUND' in result:
        return 'infected'
    if 'OK' in result:
        return 'clean'
    return 'scan_error'
