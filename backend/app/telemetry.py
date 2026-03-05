from __future__ import annotations

import time

from fastapi import Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

REQUESTS = Counter('audity_http_requests_total', 'Total API requests', ['method', 'path', 'status'])
LATENCY = Histogram('audity_http_request_latency_seconds', 'API request latency', ['method', 'path'])
RATE_LIMIT_HITS = Counter('audity_rate_limit_hits_total', 'Rate limit rejections', ['path'])
UPLOAD_QUARANTINED = Counter('audity_upload_quarantined_total', 'Uploads quarantined', ['org_id'])


async def telemetry_middleware(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed = time.perf_counter() - start
    path = request.url.path
    REQUESTS.labels(request.method, path, str(response.status_code)).inc()
    LATENCY.labels(request.method, path).observe(elapsed)
    return response


def render_metrics() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
