import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.db.session import SessionLocal
from app.main import app
from app.models.entities import Finding, RiskAcceptance, Scan


def _login(client: TestClient):
    page = client.get("/login")
    csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
    response = client.post(
        "/login",
        data={"username": "admin", "password": "ChangeMeNow!", "csrf_token": csrf},
        follow_redirects=True,
    )
    assert response.status_code == 200


def _seed_scan(client: TestClient):
    payload = json.loads(Path("fixtures/sample_scan.json").read_text())
    payload["domain_name"] = "validation-routes.local"
    response = client.post(
        "/api/v1/collector/ingest",
        headers={"Authorization": "Bearer collector-dev-token-change-me"},
        json=payload,
    )
    assert response.status_code == 200
    scan_id = response.json()["scan_id"]
    with SessionLocal() as db:
        finding = db.query(Finding).filter_by(scan_id=scan_id).first()
        assert finding is not None
        return scan_id, finding.id, finding.severity, finding.coverage_state


def _csrf_from_simulation(client: TestClient, finding_id: int):
    page = client.get(f"/findings/{finding_id}/simulate")
    assert page.status_code == 200
    return page.text.split('name="csrf_token" value="')[1].split('"')[0], page.text


def test_validation_routes_start_show_json_and_findings_badge():
    with TestClient(app) as client:
        scan_id, finding_id, severity, coverage = _seed_scan(client)
        _login(client)
        with SessionLocal() as db:
            posture_before = db.query(Scan).filter_by(id=scan_id).first().summary_json.get("posture")
            acceptance_count_before = db.query(RiskAcceptance).count()
        csrf, landing = _csrf_from_simulation(client, finding_id)
        assert "Validate Exposure" in landing
        assert "Guided Exposure Walkthrough" in landing
        assert "Live commands executed: No" in landing
        assert "Certificate requested: No" in landing
        assert "Environment changes: None" in landing
        assert "This is a safe simulation based on collected evidence" in landing
        assert 'name="command"' not in landing
        assert 'name="script"' not in landing
        start = client.post(
            f"/findings/{finding_id}/validations",
            data={"csrf_token": csrf, "mode": "evidence_replay", "command": "ignored"},
            follow_redirects=False,
        )
        assert start.status_code == 303
        validation_path = start.headers["location"]
        run_page = client.get(validation_path)
        assert "CertShield Exposure Console" in run_page.text
        assert "SIMULATION · NO CHANGES" in run_page.text
        assert "exposure-console-terminal" in run_page.text
        assert "data-validation-walkthrough" in run_page.text
        assert "validation-run-data" in run_page.text
        assert "data-console-restart" in run_page.text
        assert "data-console-restart disabled" not in run_page.text
        assert "Evidence Summary" not in run_page.text
        assert "Prompts are simulated. No commands execute. User input is display text only." not in run_page.text
        assert "walkthrough_script" in run_page.text
        assert "PS&gt;" not in run_page.text
        assert "cmd&gt;" not in run_page.text
        assert "certreq" not in run_page.text.lower()
        assert "login successful" not in run_page.text.lower()
        validation_id = int(validation_path.rsplit("/", 1)[1])
        status = client.get(f"/api/v1/validations/{validation_id}")
        data = status.json()
        assert data["finding_id"] == finding_id
        assert data["finding_url"] == f"/findings/{finding_id}/simulate"
        assert data["safety"]["live_commands_executed"] is False
        assert data["evidence"]["walkthrough_script"]
        input_csrf = run_page.text.split('data-csrf-token="')[1].split('"')[0]
        saved = client.post(
            f"/api/v1/validations/{validation_id}/walkthrough-input",
            data={"csrf_token": input_csrf, "name": "demo_identity", "value": "safe-demo;bad"},
        )
        assert saved.status_code == 200
        assert saved.json()["value"] == "safe-demo;bad"
        rejected = client.post(
            f"/api/v1/validations/{validation_id}/walkthrough-input",
            data={"csrf_token": input_csrf, "name": "demo_identity", "value": "password-token"},
        )
        assert rejected.status_code == 400
        findings = client.get("/findings")
        assert f"/validations/{validation_id}" in findings.text
        assert "Guided Walkthrough:" in findings.text
        with SessionLocal() as db:
            finding = db.query(Finding).filter_by(id=finding_id).first()
            assert finding.severity == severity
            assert finding.coverage_state == coverage
            assert db.query(RiskAcceptance).count() == acceptance_count_before
            scan = db.query(Scan).filter_by(id=scan_id).first()
            assert scan.summary_json.get("posture") == posture_before


def test_validation_route_errors_and_csrf():
    with TestClient(app) as client:
        _, finding_id, _, _ = _seed_scan(client)
        unauth = client.get(f"/findings/{finding_id}/simulate", follow_redirects=False)
        assert unauth.status_code == 303
        _login(client)
        bad_csrf = client.post(
            f"/findings/{finding_id}/validations",
            data={"csrf_token": "bad", "mode": "evidence_replay"},
        )
        assert bad_csrf.status_code == 400
        csrf, _ = _csrf_from_simulation(client, finding_id)
        bad_mode = client.post(
            f"/findings/{finding_id}/validations",
            data={"csrf_token": csrf, "mode": "live"},
        )
        assert bad_mode.status_code == 400
        assert client.get("/findings/999999/simulate").status_code == 404
        assert client.get("/validations/999999").status_code == 404
        assert client.get("/api/v1/validations/999999").status_code == 404
