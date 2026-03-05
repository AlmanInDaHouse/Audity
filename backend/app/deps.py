from collections.abc import Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import get_db
from app.models import Membership, OrgSecurityPolicy, User
from app.security import TokenClaims, get_oidc_verifier
from app.tenancy import set_current_org

bearer = HTTPBearer(auto_error=False)


class UserContext(TokenClaims):
    user_id: str


async def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: AsyncSession = Depends(get_db),
) -> UserContext:
    if creds is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Missing bearer token')

    try:
        claims = get_oidc_verifier().decode(creds.credentials)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f'Invalid token: {exc}') from exc

    user = await db.get(User, claims.sub)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='User inactive')

    membership = await db.scalar(
        select(Membership).where(Membership.user_id == claims.sub, Membership.org_id == claims.org_id)
    )
    # why this: trust-but-verify, token role must match current membership to prevent stale privilege use.
    if membership is None or membership.role.value != claims.role:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='No active membership for token')

    await set_current_org(db, claims.org_id)

    return UserContext(
        sub=claims.sub,
        email=claims.email,
        org_id=claims.org_id,
        role=claims.role,
        iss=claims.iss,
        exp=claims.exp,
        user_id=claims.sub,
    )


def require_roles(*roles: str) -> Callable[[UserContext], UserContext]:
    async def dep(ctx: UserContext = Depends(get_current_user)) -> UserContext:
        if ctx.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Insufficient role')
        return ctx

    return dep


async def require_mfa(ctx: UserContext = Depends(get_current_user), db: AsyncSession = Depends(get_db)) -> UserContext:
    policy = await db.get(OrgSecurityPolicy, ctx.org_id)
    global_required = get_settings().mfa_required_sensitive
    policy_required = bool(policy and policy.require_mfa_sensitive)
    if (global_required or policy_required) and not bool(ctx.mfa):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='MFA required')
    return ctx
