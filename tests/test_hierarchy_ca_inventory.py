from pathlib import Path


def test_ca_inventory_is_merged_into_hierarchy():
    hierarchy = Path(
        "app/templates/pki_hierarchy.html"
    ).read_text()
    base = Path("app/templates/base.html").read_text()
    main = Path("app/main.py").read_text()

    assert "PKI Hierarchy & CA Inventory" in hierarchy
    assert 'id="ca-inventory"' in hierarchy
    assert "caInventorySearch" in hierarchy

    assert 'href="/cas"' not in base

    assert (
        '"/pki-hierarchy#ca-inventory"'
        in main
    )


def test_hierarchy_service_returns_flat_inventory():
    service = Path(
        "app/services/pki_hierarchy.py"
    ).read_text()

    assert '"inventory": inventory' in service
    assert "inventory = sorted(" in service


def test_old_ca_inventory_url_redirects_to_hierarchy():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        login_page = client.get("/login")
        csrf = login_page.text.split(
            'name="csrf_token" value="'
        )[1].split('"')[0]

        client.post(
            "/login",
            data={
                "username": "admin",
                "password": "ChangeMeNow!",
                "csrf_token": csrf,
            },
            follow_redirects=True,
        )

        response = client.get(
            "/cas",
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert response.headers["location"] == (
            "/pki-hierarchy#ca-inventory"
        )
