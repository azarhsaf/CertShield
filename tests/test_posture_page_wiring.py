from pathlib import Path

from app.main import _posture_target_url


def test_health_risk_opens_health_not_hierarchy():
    record = {
        "object_type": "health_check",
        "category": "CA Health",
        "related_ca": "ROOT-CA",
    }

    assert (
        _posture_target_url(record)
        == "/pki-health#health-issues"
    )


def test_key_protection_opens_hierarchy():
    record = {
        "object_type": "ca",
        "category": "Key Protection",
        "related_ca": "ROOT-CA",
    }

    assert (
        _posture_target_url(record)
        == "/pki-hierarchy"
    )


def test_template_risk_opens_templates():
    record = {
        "object_type": "template",
        "category": "Template Risk",
        "related_template": "WebServer",
    }

    assert (
        _posture_target_url(record)
        == "/templates"
    )


def test_posture_uses_canonical_target_url():
    template = Path(
        "app/templates/pki_posture.html"
    ).read_text()

    assert 'href="{{ risk.target_url }}"' in template
    assert "Collection Gaps" in template
    assert "Governance input" in template
    assert "assurance_score" in template


def test_best_practices_not_in_navigation():
    base = Path("app/templates/base.html").read_text()

    assert 'href="/best-practices"' not in base


def test_best_practice_template_security_control_opens_templates():
    record = {
        "object_type": "best_practice",
        "category": "Best Practices",
        "object_name": "ClientAuth",
        "title": (
            "Avoid broad enrollment on "
            "authentication templates"
        ),
    }

    assert _posture_target_url(record) == "/templates"


def test_template_ownership_remains_governance_control():
    record = {
        "object_type": "best_practice",
        "category": "Best Practices",
        "object_name": "Published templates",
        "title": "Published certificate template ownership",
    }

    assert (
        _posture_target_url(record)
        == "/pki-posture#governance-controls"
    )
