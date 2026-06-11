from pathlib import Path

from app.services.governance_evidence import (
    MANUAL_CONTROL_TITLES,
)


def test_best_practices_removed_from_navigation():
    base = Path("app/templates/base.html").read_text()

    assert 'href="/best-practices"' not in base
    assert 'href="/pki-posture"' in base


def test_posture_contains_consolidated_governance():
    posture = Path(
        "app/templates/pki_posture.html"
    ).read_text()

    assert "Governance & Controls" in posture
    assert "Governance input" in posture
    assert "Accept Risk" in posture
    assert "Accepted Risk / Policy Exception" in posture


def test_root_controls_allow_customer_evidence():
    assert "Root CA should be offline" in MANUAL_CONTROL_TITLES
    assert (
        "Root CA should not be domain joined"
        in MANUAL_CONTROL_TITLES
    )
    assert (
        "Issuing CA should not run on a domain controller"
        in MANUAL_CONTROL_TITLES
    )


def test_health_does_not_show_competing_score():
    health = Path("app/templates/pki_health.html").read_text()

    assert "Overall assurance" not in health
    assert "/100" not in health
