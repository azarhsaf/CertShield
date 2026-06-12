import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.db.session import SessionLocal
from app.main import app
from app.models.entities import Finding


def _login(client: TestClient):
    page = client.get("/login")
    csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
    client.post(
        "/login",
        data={"username": "admin", "password": "ChangeMeNow!", "csrf_token": csrf},
        follow_redirects=True,
    )


def test_json_report_contains_validation_summary_and_preserves_existing_fields():
    with TestClient(app) as client:
        payload = json.loads(Path("fixtures/sample_scan.json").read_text())
        payload["domain_name"] = "validation-report.local"
        response = client.post(
            "/api/v1/collector/ingest",
            headers={"Authorization": "Bearer collector-dev-token-change-me"},
            json=payload,
        )
        assert response.status_code == 200
        scan_id = response.json()["scan_id"]
        _login(client)
        with SessionLocal() as db:
            finding = db.query(Finding).filter_by(scan_id=scan_id).first()
            finding_id = finding.id
        page = client.get(f"/findings/{finding_id}/simulate")
        csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
        started = client.post(
            f"/findings/{finding_id}/validations",
            data={"csrf_token": csrf, "mode": "evidence_replay"},
            follow_redirects=False,
        )
        assert started.status_code == 303
        report = client.get(f"/reports/{scan_id}.json").json()
        assert "coverage" in report
        assert "posture" in report
        assert "health" in report
        assert "best_practices" in report
        assert "validation_summary" in report
        assert report["validation_summary"]["total_runs"] >= 1
        matching = [item for item in report["findings"] if item["validation"]]
        assert matching
        validation = matching[0]["validation"]
        assert validation["mode"] == "evidence_replay"
        assert validation["recipe_id"] == "EVIDENCE-REPLAY-v1"
        assert validation["live_commands_executed"] is False
        assert validation["environment_changes"] is False
