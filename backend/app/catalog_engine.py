from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.config import get_settings


@dataclass
class ControlDefinition:
    id: str
    framework: str
    title: str
    description: str
    severity: str
    mapped_controls: list[str]
    evidence_requirements: list[str]
    evaluator_key: str
    tags: list[str]
    level: str


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        content = path.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        # why this: Windows editors may save YAML in latin-1/cp1252 during local setup.
        content = path.read_text(encoding='latin-1')
    return yaml.safe_load(content)


def catalog_files() -> dict[str, Path]:
    base = Path(get_settings().catalog_dir)
    return {
        'iso': base / 'iso27001_annex_a.v1.yml',
        'ens': base / 'ens_measures.v1.yml',
        'rgpd': base / 'rgpd_checklist.v1.yml',
        'mapping': base / 'control_mapping.v1.yml',
    }


def compute_catalog_checksum() -> str:
    digest = hashlib.sha256()
    for _, file_path in sorted(catalog_files().items()):
        digest.update(file_path.read_bytes())
    return digest.hexdigest()


def load_controls() -> list[ControlDefinition]:
    files = catalog_files()

    iso = _read_yaml(files['iso'])
    ens = _read_yaml(files['ens'])
    rgpd = _read_yaml(files['rgpd'])

    controls: list[ControlDefinition] = []
    for item in iso.get('controls', []):
        controls.append(
            ControlDefinition(
                id=item['id'],
                framework='ISO27001',
                title=item['title'],
                description=item['description'],
                severity=item.get('severity', 'medium'),
                mapped_controls=item.get('mapped_controls', []),
                evidence_requirements=item.get('evidence_requirements', []),
                evaluator_key=item.get('evaluator_key', 'fallback'),
                tags=item.get('tags', []),
                level=item.get('level', 'base'),
            )
        )

    for item in ens.get('measures', []):
        controls.append(
            ControlDefinition(
                id=item['id'],
                framework='ENS',
                title=item['title'],
                description=item['description'],
                severity=item.get('severity', 'medium'),
                mapped_controls=item.get('mapped_controls', []),
                evidence_requirements=item.get('evidence_requirements', []),
                evaluator_key=item.get('evaluator_key', 'fallback'),
                tags=item.get('tags', []),
                level=item.get('level', 'base'),
            )
        )

    for item in rgpd.get('checklist', []):
        control_id = f"RGPD-{item['article_or_principle']}"
        controls.append(
            ControlDefinition(
                id=control_id,
                framework='RGPD',
                title=item['question'],
                description=item.get('expected_evidence', ''),
                severity=item.get('severity', 'medium'),
                mapped_controls=item.get('mapped_controls', []),
                evidence_requirements=item.get('evidence_requirements', []),
                evaluator_key=item.get('evaluator_key', 'fallback'),
                tags=item.get('tags', []),
                level='base',
            )
        )

    return controls


def load_mapping() -> dict[str, list[str]]:
    mapping = _read_yaml(catalog_files()['mapping'])
    out: dict[str, list[str]] = {}
    for item in mapping.get('mappings', []):
        out[item['control_id']] = item.get('requirement_refs', [])
    return out
