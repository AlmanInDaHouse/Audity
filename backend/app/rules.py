from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.catalog_engine import ControlDefinition


@dataclass
class ControlResult:
    control_id: str
    title: str
    framework: str
    severity: str
    result: str
    confidence: float
    notes: str
    evidence_refs: list[str]


SEVERITY_WEIGHT = {'low': 1, 'medium': 3, 'high': 5}
RESULT_WEIGHT = {'pass': 0.0, 'partial': 0.5, 'fail': 1.0}
CRITICALITY_MULTIPLIER = {'low': 1.0, 'medium': 1.5, 'high': 2.0}


def _eval_github_branch_protection(evidence: dict[str, Any]) -> tuple[str, float, str]:
    github = evidence.get('github', {})
    protected = github.get('protected_repos', 0)
    total = github.get('repo_count', 0)
    if total == 0:
        return ('fail', 0.9, 'No GitHub repositories discovered.')
    ratio = protected / total
    if ratio >= 0.8:
        return ('pass', 0.9, f'Branch protection enabled in {protected}/{total} repositories.')
    if ratio >= 0.4:
        return ('partial', 0.7, f'Branch protection partially configured ({protected}/{total}).')
    return ('fail', 0.8, f'Branch protection weak ({protected}/{total}).')


def _eval_github_checks(evidence: dict[str, Any]) -> tuple[str, float, str]:
    github = evidence.get('github', {})
    checks = github.get('repos_with_required_checks', 0)
    total = github.get('repo_count', 0)
    if total == 0:
        return ('fail', 0.85, 'No repositories to evaluate status checks.')
    ratio = checks / total
    if ratio >= 0.75:
        return ('pass', 0.88, f'Required checks present in {checks}/{total} repositories.')
    if ratio >= 0.3:
        return ('partial', 0.68, f'Required checks incomplete ({checks}/{total}).')
    return ('fail', 0.78, f'Required checks mostly missing ({checks}/{total}).')


def _eval_google_users_groups(evidence: dict[str, Any]) -> tuple[str, float, str]:
    google = evidence.get('google_workspace', {})
    users = int(google.get('users_count', 0))
    groups = int(google.get('groups_count', 0))
    mode = google.get('mode', 'unknown')
    if users > 0 and groups > 0:
        return ('pass', 0.82, f'Workspace inventory available ({users} users, {groups} groups), mode={mode}.')
    if users > 0:
        return ('partial', 0.6, f'Users found but groups missing ({users} users), mode={mode}.')
    return ('fail', 0.7, f'Workspace inventory unavailable, mode={mode}.')


def _eval_manual_policy_uploaded(evidence: dict[str, Any]) -> tuple[str, float, str]:
    manual_items = evidence.get('manual', [])
    if manual_items:
        return ('pass', 0.75, f'{len(manual_items)} manual evidence files uploaded.')
    return ('fail', 0.7, 'No manual policy evidence uploaded.')


def _eval_fallback(_: dict[str, Any]) -> tuple[str, float, str]:
    return ('partial', 0.5, 'Evaluator not implemented; manual review required.')


EVALUATORS = {
    'github_branch_protection': _eval_github_branch_protection,
    'github_checks': _eval_github_checks,
    'google_users_groups': _eval_google_users_groups,
    'manual_policy_uploaded': _eval_manual_policy_uploaded,
    'fallback': _eval_fallback,
}


def evaluate_controls(controls: list[ControlDefinition], evidence: dict[str, Any]) -> list[ControlResult]:
    results: list[ControlResult] = []
    for control in controls:
        evaluator = EVALUATORS.get(control.evaluator_key, _eval_fallback)
        status, confidence, notes = evaluator(evidence)
        evidence_refs = control.evidence_requirements
        results.append(
            ControlResult(
                control_id=control.id,
                title=control.title,
                framework=control.framework,
                severity=control.severity,
                result=status,
                confidence=confidence,
                notes=notes,
                evidence_refs=evidence_refs,
            )
        )
    return results


def calculate_risk(results: list[ControlResult], criticality: str) -> tuple[float, str]:
    criticality_multiplier = CRITICALITY_MULTIPLIER.get(criticality, 1.5)
    weighted = 0.0
    max_weighted = 0.0
    for result in results:
        sev = SEVERITY_WEIGHT.get(result.severity, 3)
        weighted += sev * RESULT_WEIGHT.get(result.result, 1.0) * criticality_multiplier
        max_weighted += sev * 1.0 * criticality_multiplier

    if max_weighted == 0:
        return (0.0, 'low')

    score = round((weighted / max_weighted) * 100, 2)
    if score < 34:
        level = 'low'
    elif score < 67:
        level = 'medium'
    else:
        level = 'high'
    return (score, level)
