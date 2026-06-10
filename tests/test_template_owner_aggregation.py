from types import SimpleNamespace

from app.services.best_practices import assess_best_practices


def _template(name: str, published: bool):
    return SimpleNamespace(
        name=name,
        raw_json={"permissions_assessed": True},
        permissions=[],
        eku=[],
        enrollee_supplies_subject=False,
        validity_days=365,
        published_to=["Issuing-CA"] if published else [],
    )


def test_template_owner_is_one_aggregated_governance_item():
    templates = [
        _template("PublishedOne", True),
        _template("PublishedTwo", True),
        _template("UnpublishedOne", False),
    ]

    result = assess_best_practices(
        [],
        templates,
        [],
        [],
    )

    owner_items = [
        item
        for item in result["items"]
        if item["title"]
        == "Published certificate template ownership"
    ]

    assert len(owner_items) == 1
    assert owner_items[0]["affected_object"] == "Published templates"
    assert owner_items[0]["evidence"]["published_template_count"] == 2
    assert (
        owner_items[0]["evidence"][
            "templates_without_owner_count"
        ]
        == 2
    )

    assert not any(
        item["title"]
        == "Important templates should have a business owner"
        for item in result["items"]
    )
