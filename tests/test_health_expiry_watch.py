from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.services.health_assessment import _crl_item


def _ca():
    return SimpleNamespace(name="TEST-CA")


def test_unreachable_crl_without_expiry_is_not_an_expiry_watch_item():
    item, risk = _crl_item(
        _ca(),
        {
            "crl": {
                "assessed": True,
                "configured": True,
                "reachable": False,
                "urls": ["http://pki.example.test/test.crl"],
                "reason": "CRL URL is unreachable.",
            }
        },
    )

    assert item["status"] == "Critical"
    assert risk is None


def test_missing_cdp_is_not_an_expiry_watch_item():
    item, risk = _crl_item(
        _ca(),
        {
            "crl": {
                "assessed": True,
                "configured": False,
                "urls": [],
            }
        },
    )

    assert item["status"] == "Warning"
    assert risk is None


def test_crl_expiring_soon_is_an_expiry_watch_item():
    next_update = (
        datetime.now(timezone.utc) + timedelta(days=2)
    ).isoformat()

    _item, risk = _crl_item(
        _ca(),
        {
            "crl": {
                "assessed": True,
                "configured": True,
                "reachable": True,
                "urls": ["http://pki.example.test/test.crl"],
                "next_update": next_update,
            }
        },
    )

    assert risk is not None
    assert risk["type"] == "CRL"
    assert 0 <= risk["days_remaining"] <= 3
