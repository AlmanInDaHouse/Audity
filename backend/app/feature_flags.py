from __future__ import annotations

from app.config import get_settings


def enabled(flag_name: str) -> bool:
    settings = get_settings()
    return bool(getattr(settings, flag_name, False) or settings.enterprise_features_enabled)
