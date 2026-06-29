import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from app.db.session import SessionLocal
from app.main import app
from app.models.entities import MonitoringAgent, MonitoringEvent, PkiEnvironment, Scan


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


def _environment_id_from_ingest(response: object) -> int:
    scan_id = response.json().get("scan_id")
    with SessionLocal() as db:
        if scan_id:
            scan = db.query(Scan).filter_by(id=scan_id).first()
            assert scan is not None
            assert scan.environment_id is not None
            return scan.environment_id

        env = db.query(PkiEnvironment).order_by(PkiEnvironment.id.desc()).first()
        assert env is not None
        return env.id


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
        environment_id = _environment_id_from_ingest(response)

        _login(client)

        page = client.get(f"/pki-monitoring?environment_id={environment_id}")

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
        assert "request_activity" in payload
        assert payload["request_activity"]["has_live_adcs_request_events"] is False
        assert payload["request_activity"]["requests_15m"] == 0
        assert payload["request_activity"]["status"] == "Waiting for ADCS audit events"
        assert "revocation_status" in payload
        assert payload["revocation_status"]["status"] != "Not monitored"
        assert payload["revocation_status"]["source"] == "collector_scan"
        assert payload["revocation_status"]["evidence_available"] is True
        assert "evidence_freshness" in payload
        assert "pki_readiness" in payload
        assert "audit_coverage" in payload
        assert "cawe_status" in payload
        assert "privileged_access" in payload


def test_monitoring_summary_uses_recent_live_adcs_request_windows():
    with TestClient(app) as client:
        payload = json.loads(Path("fixtures/sample_scan.json").read_text())
        payload["collector_version"] = "monitoring-request-window-test"

        response = client.post(
            "/api/v1/collector/ingest",
            headers={"Authorization": "Bearer collector-dev-token-change-me"},
            json=payload,
        )
        if response.status_code == 401:
            response = client.post(
                "/api/v1/collector/ingest",
                headers={"Authorization": "Bearer collector-dev-token"},
                json=payload,
            )
        assert response.status_code == 200
        environment_id = _environment_id_from_ingest(response)

        now = datetime.now(timezone.utc)
        with SessionLocal() as db:
            agent = MonitoringAgent(
                environment_id=environment_id,
                agent_key=f"test-agent-{environment_id}",
                hostname="AZLAB2-ROOTC",
                ca_name="Azlab2-RootCA",
                status="connected",
                last_seen_at=now.replace(tzinfo=None),
                audit_success_enabled=True,
                audit_failure_enabled=True,
                audit_ready=True,
                metadata_json={
                    "services": {"certsvc": "Running"},
                    "security_log_access": True,
                },
            )
            db.add(agent)
            db.flush()
            db.add_all(
                [
                    MonitoringEvent(
                        environment_id=environment_id,
                        agent_id=agent.id,
                        event_key=f"recent-4886-{environment_id}",
                        category="adcs_audit",
                        event_type="windows_event_4886",
                        severity="info",
                        title="Request received",
                        summary="Certificate request received.",
                        actor="AZLAB2\\user",
                        occurred_at=(now - timedelta(minutes=5)).replace(tzinfo=None),
                        details_json={"event_id": "4886", "request_id": "1001"},
                    ),
                    MonitoringEvent(
                        environment_id=environment_id,
                        agent_id=agent.id,
                        event_key=f"recent-4888-{environment_id}",
                        category="adcs_audit",
                        event_type="windows_event_4888",
                        severity="warning",
                        title="Request denied",
                        summary="Certificate request denied.",
                        actor="AZLAB2\\user",
                        occurred_at=(now - timedelta(minutes=40)).replace(tzinfo=None),
                        details_json={"event_id": "4888", "request_id": "1000"},
                    ),
                    MonitoringEvent(
                        environment_id=environment_id,
                        agent_id=agent.id,
                        event_key=f"old-4886-{environment_id}",
                        category="adcs_audit",
                        event_type="windows_event_4886",
                        severity="info",
                        title="Old request received",
                        summary="Older certificate request received.",
                        actor="AZLAB2\\user",
                        occurred_at=(now - timedelta(hours=2)).replace(tzinfo=None),
                        details_json={"event_id": "4886", "request_id": "900"},
                    ),
                ]
            )
            db.commit()

        _login(client)
        client.get(f"/pki-monitoring?environment_id={environment_id}")
        api = client.get("/api/v1/monitoring/summary")
        assert api.status_code == 200
        request_activity = api.json()["request_activity"]
        assert request_activity["has_live_adcs_request_events"] is True
        assert request_activity["requests_15m"] == 1
        assert request_activity["requests_1h"] == 2
        assert request_activity["denied_1h"] == 1


def test_monitoring_summary_marks_stale_agent_heartbeat():
    with TestClient(app) as client:
        with SessionLocal() as db:
            env = PkiEnvironment(
                name="Stale Agent Lab",
                environment_key="stale-agent-lab",
                domain_name="STALE.LOCAL",
            )
            db.add(env)
            db.flush()
            agent = MonitoringAgent(
                environment_id=env.id,
                agent_key="stale-agent-key",
                hostname="STALE-CA",
                ca_name="Stale-CA",
                status="connected",
                last_seen_at=(datetime.now(timezone.utc) - timedelta(minutes=20)).replace(tzinfo=None),
                metadata_json={"services": {"certsvc": "Running"}},
            )
            db.add(agent)
            db.commit()
            environment_id = env.id

        _login(client)
        client.get(f"/pki-monitoring?environment_id={environment_id}")
        api = client.get("/api/v1/monitoring/summary")
        assert api.status_code == 200
        payload = api.json()
        assert payload["pki_readiness"]["state"] == "Agent stale"
        assert payload["pki_readiness"]["stale_threshold_seconds"] == 300


def test_monitoring_template_uses_summary_endpoint_only():
    template = Path("app/templates/pki_monitoring.html").read_text()

    assert "/api/v1/monitoring/summary" in template
    assert "/api/v1/monitoring/live" not in template
    assert "/api/v1/pki-monitoring/live" not in template
