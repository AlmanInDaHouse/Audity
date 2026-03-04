from app.reporting import render_report_html, render_report_pdf


def test_pdf_generation_has_pdf_header():
    html = render_report_html(
        {
            'audit_run_id': 'run-1',
            'project_name': 'Project',
            'org_name': 'Org',
            'risk_score': 42,
            'risk_level': 'medium',
            'total_controls': 3,
            'findings': [],
            'remediation_tasks': [],
        }
    )
    pdf = render_report_pdf(html)
    assert html.startswith('<!doctype html>') or '<html' in html.lower()
    assert pdf.startswith(b'%PDF')
