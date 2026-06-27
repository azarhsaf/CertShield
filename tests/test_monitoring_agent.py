import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.db.session import SessionLocal
from app.main import app
from app.models.entities import PkiEnvironment


def _login(client: TestClient) -> None:
    page = client.get("/login")

    csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]

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


def test_monitoring_agent_heartbeat_and_enable_command():
    with TestClient(app) as client:
        payload = json.loads(Path("fixtures/sample_scan.json").read_text())
        payload["collector_version"] = "monitoring-agent-test"

        ingest = client.post(
            "/api/v1/collector/ingest",
            headers={"Authorization": ("Bearer " "collector-dev-token-change-me")},
            json=payload,
        )

        assert ingest.status_code == 200

        with SessionLocal() as db:
            environment = db.query(PkiEnvironment).order_by(PkiEnvironment.id.desc()).first()
            assert environment is not None
            environment_id = environment.id

        heartbeat = client.post(
            "/api/v1/monitoring/agent/heartbeat",
            headers={"Authorization": ("Bearer " + get_settings().monitoring_agent_token)},
            json={
                "environment_id": environment_id,
                "agent_key": (f"adcs:{environment_id}:ca01"),
                "hostname": "CA01",
                "ca_name": "Issuing CA 01",
                "agent_version": "0.1.0",
                "state": {
                    "auditing": {
                        "policy_enabled": False,
                        "audit_filter": 0,
                        "security_log_access": True,
                    },
                    "services": {
                        "certsvc": "Running",
                        "w3svc": "Running",
                    },
                    "resources": {
                        "cpu_percent": 10,
                        "memory_percent": 30,
                        "disk_free_percent": 70,
                    },
                    "sessions": [],
                    "web_activity": [],
                },
            },
        )

        assert heartbeat.status_code == 200
        agent_id = heartbeat.json()["agent_id"]

        _login(client)

        page = client.get(f"/pki-monitoring?environment_id={environment_id}")

        assert page.status_code == 200
        assert "CA01" in page.text
        assert "Enable PKI auditing" in page.text

        csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]

        queued = client.post(
            ("/pki-monitoring/agents/" f"{agent_id}/enable-auditing" f"?environment_id={environment_id}"),
            data={"csrf_token": csrf},
            follow_redirects=False,
        )

        assert queued.status_code == 303

        command = client.get(
            ("/api/v1/monitoring/agent/commands" f"?agent_key=adcs:{environment_id}:ca01"),
            headers={"Authorization": ("Bearer " + get_settings().monitoring_agent_token)},
        )

        assert command.status_code == 200
        assert command.json()["command_type"] == "enable_ca_auditing"

        completed = client.post(
            ("/api/v1/monitoring/agent/commands/" f"{command.json()['id']}/complete"),
            headers={"Authorization": ("Bearer " + get_settings().monitoring_agent_token)},
            json={
                "agent_key": (f"adcs:{environment_id}:ca01"),
                "success": True,
                "result": {"message": ("Auditing enabled successfully")},
            },
        )

        assert completed.status_code == 200
