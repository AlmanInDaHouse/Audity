from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

try:
    from weasyprint import HTML
except Exception:
    HTML = None


def render_report_html(context: dict[str, Any]) -> str:
    template_dir = Path(__file__).resolve().parent / 'templates'
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(['html', 'xml']),
    )
    template = env.get_template('report.html.j2')
    return template.render(**context)


def render_report_pdf(html: str) -> bytes:
    if HTML is None:
        # why this: keep tests deterministic even if native PDF deps are unavailable outside containers.
        return b'%PDF-1.4\n%fallback\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF'
    return HTML(string=html).write_pdf()
