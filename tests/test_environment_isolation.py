import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.db.session import SessionLocal
from app.main import app
from app.models.entities import PkiEnvironment, Scan, ValidationRun


def _payload(domain: str, ca_name: str, template_name: str, env_name: str | None = None):
    payload = json.loads(Path("fixtures/sample_scan.json").read_text())
    payload["domain_name"] = domain
    payload["environment_name"] = env_name or domain
    payload["environment_key"] = f"adcs:{domain}:{ca_name}"
    payload["cas"][1]["name"] = ca_name
    payload["templates"][0]["name"] = template_name
    payload["templates"][0]["display_name"] = template_name
    payload["templates"][0]["published_to"] = [ca_name]
    return payload


def _login(client: TestClient):
    page = client.get("/login")
    csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
    response = client.post(
        "/login",
        data={"username": "admin", "password": "ChangeMeNow!", "csrf_token": csrf},
        follow_redirects=True,
    )
    assert response.status_code == 200


def test_two_payloads_create_environment_scoped_current_scans_and_pages_filter():
    with TestClient(app) as client:
        first = client.post(
            "/api/v1/collector/ingest",
            headers={"Authorization": "Bearer collector-dev-token-change-me"},
            json=_payload("alpha.local", "ALPHA-CA", "AlphaUserAuth", "Alpha ADCS"),
        ).json()
        second = client.post(
            "/api/v1/collector/ingest",
            headers={"Authorization": "Bearer collector-dev-token-change-me"},
            json=_payload("beta.local", "BETA-CA", "BetaUserAuth", "Beta ADCS"),
        ).json()
        with SessionLocal() as db:
            envs = db.query(PkiEnvironment).filter(PkiEnvironment.domain_name.in_(["alpha.local", "beta.local"])).all()
            assert len(envs) == 2
            alpha = next(env for env in envs if env.domain_name == "alpha.local")
            beta = next(env for env in envs if env.domain_name == "beta.local")
            assert db.query(Scan).filter_by(environment_id=alpha.id, is_current_for_environment=True).one().id == first["scan_id"]
            assert db.query(Scan).filter_by(environment_id=beta.id, is_current_for_environment=True).one().id == second["scan_id"]
        _login(client)
        alpha_page = client.get(f"/templates?environment_id={alpha.id}")
        assert "AlphaUserAuth" in alpha_page.text
        assert "BetaUserAuth" not in alpha_page.text
        beta_page = client.get(f"/pki-hierarchy?environment_id={beta.id}")
        assert "BETA-CA" in beta_page.text
        assert "ALPHA-CA" not in beta_page.text


def test_rescan_same_environment_increments_sequence_and_report_metadata():
    with TestClient(app) as client:
        payload = _payload("sequence.local", "SEQ-CA", "SeqUserAuth", "Sequence ADCS")
        first = client.post("/api/v1/collector/ingest", headers={"Authorization": "Bearer collector-dev-token-change-me"}, json=payload).json()
        second = client.post("/api/v1/collector/ingest", headers={"Authorization": "Bearer collector-dev-token-change-me"}, json=payload).json()
        with SessionLocal() as db:
            latest = db.query(Scan).filter_by(id=second["scan_id"]).one()
            prior = db.query(Scan).filter_by(id=first["scan_id"]).one()
            assert latest.environment_id == prior.environment_id
            assert latest.scan_sequence == prior.scan_sequence + 1
            assert latest.previous_scan_id == prior.id
            assert latest.is_current_for_environment is True
            assert prior.is_current_for_environment is False
        _login(client)
        report = client.get(f"/reports/{second['scan_id']}.json").json()
        assert report["environment"]["environment_key"] == "adcs:sequence.local:seq-ca"
        assert report["scan_metadata"]["previous_scan_id"] == first["scan_id"]


def test_ejbca_payload_can_create_generic_environment():
    with TestClient(app) as client:
        payload = {
            "collector_type": "ejbca",
            "environment_name": "EJBCA GID Prod",
            "environment_key": "ejbca:gid-prod:ejbca-ca-01",
            "domain_name": "gid-prod",
            "source_host": "ejbca-collector",
            "cas": [{"name": "EJBCA-CA-01", "dns_name": "ejbca.example", "status": "online", "config": {}}],
            "templates": [],
            "issued_certificates": [],
        }
        response = client.post("/api/v1/collector/ingest", headers={"Authorization": "Bearer collector-dev-token-change-me"}, json=payload)
        assert response.status_code == 200
        with SessionLocal() as db:
            env = db.query(PkiEnvironment).filter_by(environment_key="ejbca:gid-prod:ejbca-ca-01").one()
            assert env.collector_type == "ejbca"
            assert env.name == "EJBCA GID Prod"


def test_validation_run_is_tied_to_environment():
    with TestClient(app) as client:
        scan = client.post(
            "/api/v1/collector/ingest",
            headers={"Authorization": "Bearer collector-dev-token-change-me"},
            json=_payload("validation-env.local", "VAL-CA", "ValUserAuth", "Validation Env"),
        ).json()
        _login(client)
        with SessionLocal() as db:
            finding = db.query(Scan).filter_by(id=scan["scan_id"]).one().findings[0]
            env_id = finding.scan.environment_id
        page = client.get(f"/findings/{finding.id}/simulate")
        csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
        started = client.post(f"/findings/{finding.id}/validations", data={"csrf_token": csrf, "mode": "evidence_replay"}, follow_redirects=False)
        validation_id = int(started.headers["location"].rsplit("/", 1)[1])
        with SessionLocal() as db:
            run = db.query(ValidationRun).filter_by(id=validation_id).one()
            assert run.environment_id == env_id
