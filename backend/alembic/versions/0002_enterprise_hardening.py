"""enterprise hardening and multi-tenant rls

Revision ID: 0002_enterprise_hardening
Revises: 0001_initial
Create Date: 2026-03-05
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = '0002_enterprise_hardening'
down_revision = '0001_initial'
branch_labels = None
depends_on = None


def _enable_rls(table: str, policy_sql: str) -> None:
    op.execute(f'ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;')
    op.execute(f'ALTER TABLE {table} FORCE ROW LEVEL SECURITY;')
    op.execute(f'DROP POLICY IF EXISTS p_{table}_tenant ON {table};')
    op.execute(f'CREATE POLICY p_{table}_tenant ON {table} USING ({policy_sql});')


def upgrade() -> None:
    # why this: support upgrade on partially initialized databases where roleenum exists
    # or migration is retried after a failed run.
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'roleenum') THEN
                CREATE TYPE roleenum AS ENUM ('org_admin', 'auditor', 'client_viewer');
            END IF;
        END
        $$;
        """
    )
    op.execute("ALTER TYPE roleenum ADD VALUE IF NOT EXISTS 'security_reviewer';")
    op.execute("ALTER TYPE roleenum ADD VALUE IF NOT EXISTS 'remediation_manager';")

    op.add_column('users', sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column('projects', sa.Column('tags_json', sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")))
    op.add_column(
        'audit_runs',
        sa.Column('signature_bundle_json', sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
    )

    op.add_column('evidence_items', sa.Column('scan_status', sa.String(32), nullable=False, server_default='clean'))
    op.add_column('evidence_items', sa.Column('quarantine_reason', sa.Text(), nullable=True))
    op.add_column('evidence_items', sa.Column('immutable', sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column('evidence_items', sa.Column('retention_until', sa.DateTime(timezone=True), nullable=True))
    op.add_column('evidence_items', sa.Column('version', sa.Integer(), nullable=False, server_default='1'))
    op.add_column('evidence_items', sa.Column('supersedes_evidence_id', sa.String(36), nullable=True))
    op.add_column(
        'evidence_items',
        sa.Column('manifest_json', sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
    )
    op.add_column(
        'evidence_items',
        sa.Column('signature_bundle_json', sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
    )
    op.create_foreign_key(
        'fk_evidence_items_supersedes_evidence_id',
        'evidence_items',
        'evidence_items',
        ['supersedes_evidence_id'],
        ['id'],
        ondelete='SET NULL',
    )

    op.add_column('remediation_tasks', sa.Column('sla_due_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('remediation_tasks', sa.Column('exception_waiver_id', sa.String(36), nullable=True))

    op.create_table(
        'auth_sessions',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('org_id', sa.String(36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('refresh_token_hash', sa.String(128), nullable=False, unique=True),
        sa.Column('rotated_from_session_id', sa.String(36), sa.ForeignKey('auth_sessions.id', ondelete='SET NULL'), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_auth_sessions_org_id', 'auth_sessions', ['org_id'])
    op.create_index('ix_auth_sessions_user_id', 'auth_sessions', ['user_id'])

    op.create_table(
        'org_security_policies',
        sa.Column('org_id', sa.String(36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('require_mfa_sensitive', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('max_upload_bytes', sa.Integer(), nullable=False, server_default=str(20 * 1024 * 1024)),
        sa.Column('retention_days', sa.Integer(), nullable=False, server_default='365'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        'scim_access_tokens',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('org_id', sa.String(36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('token_secret_ref', sa.String(255), nullable=False),
        sa.Column('description', sa.String(255), nullable=False, server_default='SCIM token'),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_scim_access_tokens_org_id', 'scim_access_tokens', ['org_id'])

    op.create_table(
        'role_permissions',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('org_id', sa.String(36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True),
        sa.Column(
            'role',
            postgresql.ENUM(
                'org_admin',
                'auditor',
                'client_viewer',
                'security_reviewer',
                'remediation_manager',
                name='roleenum',
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column('resource', sa.String(64), nullable=False),
        sa.Column('action', sa.String(64), nullable=False),
        sa.Column('conditions_json', sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('org_id', 'role', 'resource', 'action', name='uq_role_permissions'),
    )
    op.create_index('ix_role_permissions_org_id', 'role_permissions', ['org_id'])

    op.create_table(
        'finding_approvals',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('org_id', sa.String(36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('finding_id', sa.String(36), sa.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False),
        sa.Column('requested_by_user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=False),
        sa.Column('approved_by_user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('status', sa.String(32), nullable=False, server_default='pending'),
        sa.Column('notes', sa.Text(), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_finding_approvals_org_id', 'finding_approvals', ['org_id'])
    op.create_index('ix_finding_approvals_finding_id', 'finding_approvals', ['finding_id'])

    op.create_table(
        'waivers',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('org_id', sa.String(36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('finding_id', sa.String(36), sa.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False),
        sa.Column('created_by_user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_waivers_org_id', 'waivers', ['org_id'])
    op.create_index('ix_waivers_finding_id', 'waivers', ['finding_id'])

    op.create_table(
        'remediation_comments',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('org_id', sa.String(36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('remediation_task_id', sa.String(36), sa.ForeignKey('remediation_tasks.id', ondelete='CASCADE'), nullable=False),
        sa.Column('author_user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_remediation_comments_org_id', 'remediation_comments', ['org_id'])
    op.create_index('ix_remediation_comments_remediation_task_id', 'remediation_comments', ['remediation_task_id'])

    op.create_table(
        'outbound_integrations',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('org_id', sa.String(36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('kind', sa.String(64), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('config_json', sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column('secret_ref', sa.String(255), nullable=True),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_outbound_integrations_org_id', 'outbound_integrations', ['org_id'])

    op.create_table(
        'pricing_plans',
        sa.Column('org_id', sa.String(36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('plan_code', sa.String(64), nullable=False, server_default='starter'),
        sa.Column('max_assets', sa.Integer(), nullable=False, server_default='50'),
        sa.Column('max_upload_bytes', sa.Integer(), nullable=False, server_default=str(20 * 1024 * 1024)),
        sa.Column('modules_json', sa.JSON(), nullable=False, server_default=sa.text("'{}'::json")),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        'audit_packages',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('org_id', sa.String(36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('project_id', sa.String(36), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
        sa.Column('audit_run_id', sa.String(36), sa.ForeignKey('audit_runs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('evidence_id', sa.String(36), sa.ForeignKey('evidence_items.id', ondelete='SET NULL'), nullable=True),
        sa.Column('status', sa.String(32), nullable=False, server_default='ready'),
        sa.Column('created_by_user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_audit_packages_org_id', 'audit_packages', ['org_id'])
    op.create_index('ix_audit_packages_project_id', 'audit_packages', ['project_id'])
    op.create_index('ix_audit_packages_audit_run_id', 'audit_packages', ['audit_run_id'])

    # Seed per-org defaults so policies exist immediately after migration.
    op.execute(
        """
        INSERT INTO org_security_policies (org_id, require_mfa_sensitive, max_upload_bytes, retention_days, created_at, updated_at)
        SELECT id, false, 20971520, 365, now(), now()
        FROM organizations
        ON CONFLICT (org_id) DO NOTHING
        """
    )
    op.execute(
        """
        INSERT INTO pricing_plans (org_id, plan_code, max_assets, max_upload_bytes, modules_json, created_at, updated_at)
        SELECT id, 'starter', 50, 20971520, '{}'::json, now(), now()
        FROM organizations
        ON CONFLICT (org_id) DO NOTHING
        """
    )

    tenant_clause = (
        "org_id = current_setting('app.current_org_id', true) "
        "OR coalesce(current_setting('app.current_org_id', true), '') = ''"
    )
    _enable_rls('projects', tenant_clause)
    _enable_rls('integrations', tenant_clause)
    _enable_rls('audit_runs', tenant_clause)
    _enable_rls('findings', tenant_clause)
    _enable_rls('evidence_items', tenant_clause)
    _enable_rls('remediation_tasks', tenant_clause)
    _enable_rls('audit_log_entries', tenant_clause)
    _enable_rls('memberships', tenant_clause)
    _enable_rls('org_security_policies', tenant_clause)
    _enable_rls('scim_access_tokens', tenant_clause)
    _enable_rls('finding_approvals', tenant_clause)
    _enable_rls('waivers', tenant_clause)
    _enable_rls('remediation_comments', tenant_clause)
    _enable_rls('outbound_integrations', tenant_clause)
    _enable_rls('pricing_plans', tenant_clause)
    _enable_rls('audit_packages', tenant_clause)
    _enable_rls('control_catalogs', f"{tenant_clause} OR is_global = true")
    _enable_rls('role_permissions', f"{tenant_clause} OR org_id IS NULL")
    _enable_rls('auth_sessions', tenant_clause)


def downgrade() -> None:
    for table in [
        'auth_sessions',
        'org_security_policies',
        'scim_access_tokens',
        'role_permissions',
        'finding_approvals',
        'waivers',
        'remediation_comments',
        'outbound_integrations',
        'pricing_plans',
        'audit_packages',
    ]:
        op.execute(f'ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;')

    op.drop_index('ix_audit_packages_audit_run_id', table_name='audit_packages')
    op.drop_index('ix_audit_packages_project_id', table_name='audit_packages')
    op.drop_index('ix_audit_packages_org_id', table_name='audit_packages')
    op.drop_table('audit_packages')

    op.drop_table('pricing_plans')

    op.drop_index('ix_outbound_integrations_org_id', table_name='outbound_integrations')
    op.drop_table('outbound_integrations')

    op.drop_index('ix_remediation_comments_remediation_task_id', table_name='remediation_comments')
    op.drop_index('ix_remediation_comments_org_id', table_name='remediation_comments')
    op.drop_table('remediation_comments')

    op.drop_index('ix_waivers_finding_id', table_name='waivers')
    op.drop_index('ix_waivers_org_id', table_name='waivers')
    op.drop_table('waivers')

    op.drop_index('ix_finding_approvals_finding_id', table_name='finding_approvals')
    op.drop_index('ix_finding_approvals_org_id', table_name='finding_approvals')
    op.drop_table('finding_approvals')

    op.drop_index('ix_role_permissions_org_id', table_name='role_permissions')
    op.drop_table('role_permissions')

    op.drop_index('ix_scim_access_tokens_org_id', table_name='scim_access_tokens')
    op.drop_table('scim_access_tokens')

    op.drop_table('org_security_policies')

    op.drop_index('ix_auth_sessions_user_id', table_name='auth_sessions')
    op.drop_index('ix_auth_sessions_org_id', table_name='auth_sessions')
    op.drop_table('auth_sessions')

    op.drop_constraint('fk_evidence_items_supersedes_evidence_id', 'evidence_items', type_='foreignkey')
    op.drop_column('evidence_items', 'signature_bundle_json')
    op.drop_column('evidence_items', 'manifest_json')
    op.drop_column('evidence_items', 'supersedes_evidence_id')
    op.drop_column('evidence_items', 'version')
    op.drop_column('evidence_items', 'retention_until')
    op.drop_column('evidence_items', 'immutable')
    op.drop_column('evidence_items', 'quarantine_reason')
    op.drop_column('evidence_items', 'scan_status')

    op.drop_column('audit_runs', 'signature_bundle_json')
    op.drop_column('projects', 'tags_json')
    op.drop_column('users', 'is_active')
    op.drop_column('remediation_tasks', 'exception_waiver_id')
    op.drop_column('remediation_tasks', 'sla_due_at')
