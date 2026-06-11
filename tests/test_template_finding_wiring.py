from pathlib import Path
from types import SimpleNamespace

from app.main import _posture_target_url
from app.services.risk_acceptance import (
    finding_fingerprint,
)


def _finding(title: str):
    return SimpleNamespace(
        esc_category="ESC1-like",
        affected_object="ClientAuth",
        title=title,
        rule_id="RULE",
        evidence_json={
            "template": "ClientAuth",
        },
    )


def test_two_findings_on_same_template_have_different_fingerprints():
    first = _finding("Broad enrollment allowed")
    second = _finding("Requester supplies subject")

    assert (
        finding_fingerprint(first)
        != finding_fingerprint(second)
    )


def test_posture_opens_exact_finding():
    record = {
        "object_type": "finding",
        "category": "Template Risk",
        "related_template": "ClientAuth",
        "related_finding": 123,
    }

    assert (
        _posture_target_url(record)
        == "/findings#finding-123"
    )


def test_template_page_uses_exact_finding_links():
    template = Path(
        "app/templates/templates.html"
    ).read_text()
    findings = Path(
        "app/templates/findings.html"
    ).read_text()

    assert 'href="{{ issue.url }}"' in template
    assert "View all findings for this template" in template
    assert 'id="finding-{{ f.id }}"' in findings
