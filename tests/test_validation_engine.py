from app.db.session import SessionLocal
from app.models.entities import Finding, Scan
from app.services.validation_engine import (
    SAFETY_METADATA,
    build_replay_steps,
    calculate_replay_result,
    create_evidence_replay,
    get_validation_history,
)


def _finding(**overrides):
    values = {
        "id": 1,
        "scan_id": 1,
        "rule_id": "ESC-TEST",
        "severity": "Critical",
        "confidence": "high",
        "coverage_state": "detected",
        "title": "Test exposure",
        "affected_object": "ClientAuth",
        "trigger_conditions": "Stored trigger",
        "rationale": "Stored rationale",
        "evidence_json": {"purpose": "Client Authentication"},
        "remediation": "Review template",
        "simulation_summary": "Replayable evidence exists.",
        "simulation_json": {
            "path": "ESC1-like",
            "preconditions_met": ["Authentication-capable template purpose"],
            "missing_or_unconfirmed": [],
            "blast_radius": "Domain authentication may be possible",
            "confidence": "high",
        },
    }
    values.update(overrides)
    return Finding(**values)


def test_result_calculation_exposure_indicated_for_complete_detected_evidence():
    result, confidence, summary = calculate_replay_result(_finding())
    assert result == "exposure_indicated"
    assert confidence == "high"
    assert "not live confirmation" in summary


def test_missing_evidence_returns_incomplete_not_no_exposure():
    result, _, _ = calculate_replay_result(_finding(simulation_json={}, evidence_json={}))
    assert result == "evidence_incomplete"
    assert result != "no_exposure_indicated"


def test_build_replay_steps_are_ordered_and_safe():
    steps = build_replay_steps(_finding())
    assert [step["sequence"] for step in steps] == list(range(1, len(steps) + 1))
    assert steps[0]["step_name"] == "Load collected finding evidence"
    assert any(step["step_name"] == "Apply safety boundary" for step in steps)
    safety_step = next(step for step in steps if step["step_name"] == "Apply safety boundary")
    assert safety_step["evidence_json"]["live_commands_executed"] is False


def test_create_replay_persists_run_steps_and_separate_history():
    with SessionLocal() as db:
        scan = Scan(domain_name="validation-engine.local", summary_json={}, coverage_json={})
        db.add(scan)
        db.flush()
        first = _finding(id=None, scan_id=scan.id, affected_object="TemplateA")
        second = _finding(id=None, scan_id=scan.id, affected_object="TemplateB")
        db.add_all([first, second])
        db.flush()
        run = create_evidence_replay(db, first, "pytest")
        assert run.status == "completed"
        assert run.result == "exposure_indicated"
        assert run.safety_json == SAFETY_METADATA
        assert len(run.steps) >= 4
        assert get_validation_history(db, first.id)[0].id == run.id
        assert get_validation_history(db, second.id) == []
