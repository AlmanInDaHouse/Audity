from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models import AuthSession, Membership, User
from app.security import hash_refresh_token, new_refresh_token


def ensure_utc_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


async def issue_session(db: AsyncSession, *, user: User, org_id: str) -> tuple[str, AuthSession]:
    settings = get_settings()
    refresh_token = new_refresh_token()
    session = AuthSession(
        org_id=org_id,
        user_id=user.id,
        refresh_token_hash=hash_refresh_token(refresh_token),
        expires_at=datetime.now(UTC) + timedelta(hours=settings.refresh_token_ttl_hours),
    )
    db.add(session)
    await db.flush()
    return refresh_token, session


async def rotate_session(db: AsyncSession, *, refresh_token: str) -> tuple[AuthSession, str, User, Membership]:
    hashed = hash_refresh_token(refresh_token)
    session = await db.scalar(select(AuthSession).where(AuthSession.refresh_token_hash == hashed))
    if session is None:
        raise ValueError('Session not found')
    if session.revoked_at is not None:
        raise ValueError('Session revoked')
    now = datetime.now(UTC)
    exp = ensure_utc_aware(session.expires_at)
    if exp < now:
        raise ValueError('Session expired')

    user = await db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise ValueError('User inactive')

    membership = await db.scalar(select(Membership).where(Membership.user_id == user.id, Membership.org_id == session.org_id))
    if membership is None:
        raise ValueError('Membership missing')

    replacement_token = new_refresh_token()
    replacement = AuthSession(
        org_id=session.org_id,
        user_id=session.user_id,
        refresh_token_hash=hash_refresh_token(replacement_token),
        rotated_from_session_id=session.id,
        expires_at=datetime.now(UTC) + timedelta(hours=get_settings().refresh_token_ttl_hours),
    )
    session.revoked_at = datetime.now(UTC)
    db.add(replacement)
    await db.flush()
    return replacement, replacement_token, user, membership


async def revoke_session(db: AsyncSession, *, refresh_token: str) -> bool:
    hashed = hash_refresh_token(refresh_token)
    session = await db.scalar(select(AuthSession).where(AuthSession.refresh_token_hash == hashed))
    if session is None:
        return False
    session.revoked_at = datetime.now(UTC)
    await db.flush()
    return True
