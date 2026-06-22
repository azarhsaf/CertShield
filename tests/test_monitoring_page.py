import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


def _login(client: TestClient) -> None:
    page = client.get("/login")

    csrf = page.text.split(
        'name="csrf_token" value="'
    )[1].split('"')[0]

    response = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "ChangeMeNow!",
            "csrf_token": csrf,
        },
        follow_redirects=True,
    )

    assert response.status_code == 200


def test_monitoring_page_and_snapshot_api():
    with TestClient(app) as client:
        payload = json.loads(
            Path("fixtures/sample_scan.json").read_text()
        )

        payload["collector_version"] = (
            "monitoring-page-test"
        )

        response = client.post(
            "/api/v1/collector/ingest",
            headers={
                "Authorization": (
                    "Bearer "
                    "collector-dev-token-change-me"
                )
            },
            json=payload,
        )

        if response.status_code == 401:
            response = client.post(
                "/api/v1/collector/ingest",
                headers={
                    "Authorization": (
                        "Bearer collector-dev-token"
                    )
                },
                json=payload,
            )

        assert response.status_code == 200

        _login(client)

        page = client.get("/pki-monitoring")

        assert page.status_code == 200
        assert "PKI Monitoring" in page.text
        assert "PKI Live Operations Centre" in page.text
        assert "Snapshot mode" in page.text
        assert "What needs attention now?" in page.text
        assert "Activity timeline" in page.text

        api = client.get(
            "/api/v1/monitoring/summary"
        )

        assert api.status_code == 200

        payload = api.json()

        assert payload["mode"] == "snapshot"
        assert payload["agent_connected"] is False
        assert "counters" in payload
        assert "outcomes" in payload
        assert "ca_nodes" in payload
        assert "events" in payload
