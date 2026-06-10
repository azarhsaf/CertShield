from app.services.assessment_registry import _is_confirmed_risk, _is_coverage_gap


def test_not_assessed_is_coverage_gap_not_confirmed_risk():
    record = {
        "severity": "High",
        "original_status": "Not Assessed",
    }

    assert _is_coverage_gap(record) is True
    assert _is_confirmed_risk(record) is False


def test_confirmed_high_risk_is_not_coverage_gap():
    record = {
        "severity": "High",
        "original_status": "High Risk",
    }

    assert _is_confirmed_risk(record) is True
    assert _is_coverage_gap(record) is False


def test_warning_medium_is_not_top_confirmed_risk():
    record = {
        "severity": "Medium",
        "original_status": "Warning",
    }

    assert _is_confirmed_risk(record) is False
    assert _is_coverage_gap(record) is False
