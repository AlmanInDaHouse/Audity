"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-03-04
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '0001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    role_enum = sa.Enum('org_admin', 'auditor', 'client_viewer', name='roleenum')
    criticality_enum = sa.Enum('low', 'medium', 'high', name='criticalityenum')
    audit_status_enum = sa.Enum('queued', 'running', 'completed', 'failed', name='auditstatusenum')
    finding_status_enum = sa.Enum('open', 'accepted', 'resolved', name='findingstatusenum')
    severity_enum = sa.Enum('low', 'medium', 'high', name='severityenum')
    result_enum = sa.Enum('pass', 'fail', 'partial', name='resultenum')

    op.create_table(
        'organizations',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False, unique=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        'users',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('email', sa.String(255), nullable=False, unique=True),
        sa.Column('display_name', sa.String(255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        'memberships',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('org_id', sa.String(36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('role', role_enum, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('org_id', 'user_id', name='uq_membership_org_user'),
    )

    op.create_table(
        'projects',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('org_id', sa.String(36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('criticality', criticality_enum, nullable=False, server_default='medium'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_projects_org_id', 'projects', ['org_id'])

    op.create_table(
        'integrations',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('org_id', sa.String(36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('project_id', sa.String(36), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
        sa.Column('provider', sa.String(64), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('config_json', sa.JSON(), nullable=False),
        sa.Column('secret_ref', sa.String(255), nullable=True),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_integrations_org_id', 'integrations', ['org_id'])
    op.create_index('ix_integrations_project_id', 'integrations', ['project_id'])

    op.create_table(
        'control_catalogs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('org_id', sa.String(36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('framework', sa.String(64), nullable=False),
        sa.Column('version', sa.String(64), nullable=False),
        sa.Column('checksum', sa.String(128), nullable=False),
        sa.Column('source_path', sa.String(512), nullable=False),
        sa.Column('is_global', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_control_catalogs_org_id', 'control_catalogs', ['org_id'])

    op.create_table(
        'evidence_items',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('org_id', sa.String(36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('project_id', sa.String(36), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
        sa.Column('integration_id', sa.String(36), sa.ForeignKey('integrations.id', ondelete='SET NULL'), nullable=True),
        sa.Column('item_type', sa.String(64), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('object_key', sa.String(512), nullable=False),
        sa.Column('sha256', sa.String(64), nullable=False),
        sa.Column('metadata_json', sa.JSON(), nullable=False),
        sa.Column('created_by_user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_evidence_items_org_id', 'evidence_items', ['org_id'])
    op.create_index('ix_evidence_items_project_id', 'evidence_items', ['project_id'])

    op.create_table(
        'audit_runs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('org_id', sa.String(36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('project_id', sa.String(36), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
        sa.Column('triggered_by_user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('status', audit_status_enum, nullable=False, server_default='queued'),
        sa.Column('catalog_version', sa.String(64), nullable=False, server_default='v1'),
        sa.Column('progress_json', sa.JSON(), nullable=False),
        sa.Column('summary_json', sa.JSON(), nullable=False),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('risk_level', sa.String(16), nullable=True),
        sa.Column('report_evidence_id', sa.String(36), sa.ForeignKey('evidence_items.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_audit_runs_org_id', 'audit_runs', ['org_id'])
    op.create_index('ix_audit_runs_project_id', 'audit_runs', ['project_id'])
    op.create_index('ix_audit_runs_status', 'audit_runs', ['status'])

    op.add_column('evidence_items', sa.Column('audit_run_id', sa.String(36), sa.ForeignKey('audit_runs.id', ondelete='SET NULL'), nullable=True))
    op.create_index('ix_evidence_items_audit_run_id', 'evidence_items', ['audit_run_id'])

    op.create_table(
        'findings',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('org_id', sa.String(36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('project_id', sa.String(36), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
        sa.Column('audit_run_id', sa.String(36), sa.ForeignKey('audit_runs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('control_id', sa.String(128), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('severity', severity_enum, nullable=False, server_default='medium'),
        sa.Column('result', result_enum, nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('notes', sa.Text(), nullable=False, server_default=''),
        sa.Column('status', finding_status_enum, nullable=False, server_default='open'),
        sa.Column('evidence_refs_json', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_findings_org_id', 'findings', ['org_id'])
    op.create_index('ix_findings_project_id', 'findings', ['project_id'])
    op.create_index('ix_findings_audit_run_id', 'findings', ['audit_run_id'])

    op.create_table(
        'remediation_tasks',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('org_id', sa.String(36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('project_id', sa.String(36), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
        sa.Column('audit_run_id', sa.String(36), sa.ForeignKey('audit_runs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('finding_id', sa.String(36), sa.ForeignKey('findings.id', ondelete='SET NULL'), nullable=True),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('status', sa.String(32), nullable=False, server_default='open'),
        sa.Column('assignee_user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('due_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_remediation_tasks_org_id', 'remediation_tasks', ['org_id'])
    op.create_index('ix_remediation_tasks_project_id', 'remediation_tasks', ['project_id'])
    op.create_index('ix_remediation_tasks_audit_run_id', 'remediation_tasks', ['audit_run_id'])

    op.create_table(
        'audit_log_entries',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('org_id', sa.String(36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('actor_user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('action', sa.String(128), nullable=False),
        sa.Column('entity_type', sa.String(64), nullable=False),
        sa.Column('entity_id', sa.String(64), nullable=False),
        sa.Column('payload_json', sa.JSON(), nullable=False),
        sa.Column('prev_hash', sa.String(64), nullable=False),
        sa.Column('entry_hash', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_audit_log_entries_org_id', 'audit_log_entries', ['org_id'])
    op.create_index('ix_audit_log_entries_created_at', 'audit_log_entries', ['created_at'])

    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_audit_log_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'audit_log_entries is append-only';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_audit_log_no_update
        BEFORE UPDATE OR DELETE ON audit_log_entries
        FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_mutation();
        """
    )


def downgrade() -> None:
    op.execute('DROP TRIGGER IF EXISTS trg_audit_log_no_update ON audit_log_entries;')
    op.execute('DROP FUNCTION IF EXISTS prevent_audit_log_mutation();')

    op.drop_index('ix_audit_log_entries_created_at', table_name='audit_log_entries')
    op.drop_index('ix_audit_log_entries_org_id', table_name='audit_log_entries')
    op.drop_table('audit_log_entries')

    op.drop_index('ix_remediation_tasks_audit_run_id', table_name='remediation_tasks')
    op.drop_index('ix_remediation_tasks_project_id', table_name='remediation_tasks')
    op.drop_index('ix_remediation_tasks_org_id', table_name='remediation_tasks')
    op.drop_table('remediation_tasks')

    op.drop_index('ix_findings_audit_run_id', table_name='findings')
    op.drop_index('ix_findings_project_id', table_name='findings')
    op.drop_index('ix_findings_org_id', table_name='findings')
    op.drop_table('findings')

    op.drop_index('ix_evidence_items_audit_run_id', table_name='evidence_items')

    op.drop_index('ix_audit_runs_status', table_name='audit_runs')
    op.drop_index('ix_audit_runs_project_id', table_name='audit_runs')
    op.drop_index('ix_audit_runs_org_id', table_name='audit_runs')
    op.drop_table('audit_runs')

    op.drop_index('ix_evidence_items_project_id', table_name='evidence_items')
    op.drop_index('ix_evidence_items_org_id', table_name='evidence_items')
    op.drop_table('evidence_items')

    op.drop_index('ix_control_catalogs_org_id', table_name='control_catalogs')
    op.drop_table('control_catalogs')

    op.drop_index('ix_integrations_project_id', table_name='integrations')
    op.drop_index('ix_integrations_org_id', table_name='integrations')
    op.drop_table('integrations')

    op.drop_index('ix_projects_org_id', table_name='projects')
    op.drop_table('projects')

    op.drop_table('memberships')
    op.drop_table('users')
    op.drop_table('organizations')

    bind = op.get_bind()
    sa.Enum(name='resultenum').drop(bind, checkfirst=True)
    sa.Enum(name='severityenum').drop(bind, checkfirst=True)
    sa.Enum(name='findingstatusenum').drop(bind, checkfirst=True)
    sa.Enum(name='auditstatusenum').drop(bind, checkfirst=True)
    sa.Enum(name='criticalityenum').drop(bind, checkfirst=True)
    sa.Enum(name='roleenum').drop(bind, checkfirst=True)
