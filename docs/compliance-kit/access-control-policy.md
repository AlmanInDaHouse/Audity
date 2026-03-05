# Access Control Policy (Template)

## Purpose
Define least-privilege access requirements for Audity personnel and tenant admins.

## Scope
- Production, staging, development environments.
- Human users, service accounts, CI/CD identities.

## Controls
1. SSO required for workforce accounts.
2. MFA required for privileged roles.
3. RBAC + ABAC enforced in product APIs.
4. Quarterly access review for admin privileges.
5. Immediate revocation on termination/role change.

## Evidence
- Audit logs (`audit_log_entries`).
- SCIM provisioning/deprovisioning records.
- Session revocation logs.
