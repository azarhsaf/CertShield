import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


def _login(client: TestClient) -> None:
    login_page = client.get("/login")

    csrf = login_page.text.split(
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


def test_customer_pdf_report_download():
    with TestClient(app) as client:
        payload = json.loads(
            Path("fixtures/sample_scan.json").read_text()
        )

        payload["collector_version"] = (
            "pdf-report-test"
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

        scan_id = response.json()["scan_id"]

        _login(client)

        pdf = client.get(
            f"/reports/{scan_id}.pdf"
        )

        assert pdf.status_code == 200
        assert pdf.headers["content-type"].startswith(
            "application/pdf"
        )
        assert pdf.content.startswith(b"%PDF")
        assert len(pdf.content) > 5000
        assert "attachment;" in pdf.headers[
            "content-disposition"
        ]

        report = client.get(
            f"/reports/{scan_id}.json"
        ).json()

        environment_id = report["environment"]["id"]

        latest_pdf = client.get(
            "/reports/environment/"
            f"{environment_id}/latest.pdf"
        )

        assert latest_pdf.status_code == 200
        assert latest_pdf.content.startswith(b"%PDF")
