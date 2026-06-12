from sqlalchemy import inspect

from app.db.migrate import run_ddl_migrations
from app.db.session import SessionLocal, engine
from app.models.entities import Finding, Scan, ValidationRun, ValidationStep


def test_validation_models_and_migration_tables_exist():
    with SessionLocal() as db:
        run_ddl_migrations(db)
        run_ddl_migrations(db)
    inspector = inspect(engine)
    assert "validation_runs" in inspector.get_table_names()
    assert "validation_steps" in inspector.get_table_names()
    run_cols = {col["name"] for col in inspector.get_columns("validation_runs")}
    step_cols = {col["name"] for col in inspector.get_columns("validation_steps")}
    assert {"finding_id", "scan_id", "mode", "recipe_id", "recipe_hash", "correlation_id"} <= run_cols
    assert {"validation_run_id", "sequence", "step_name", "status", "message"} <= step_cols


def test_validation_run_relationships_can_persist():
    with SessionLocal() as db:
        scan = Scan(domain_name="validation-model.local", summary_json={}, coverage_json={})
        db.add(scan)
        db.flush()
        finding = Finding(
            scan_id=scan.id,
            rule_id="MODEL-1",
            severity="High",
            title="Model validation finding",
            affected_object="ModelTemplate",
            rationale="Model test",
            remediation="Review",
        )
        db.add(finding)
        db.flush()
        run = ValidationRun(
            finding_id=finding.id,
            scan_id=scan.id,
            recipe_id="EVIDENCE-REPLAY-v1",
            recipe_hash="abc",
            target="ModelTemplate",
            status="completed",
            result="evidence_incomplete",
            confidence="low",
            correlation_id=f"model-{scan.id}-{finding.id}",
            safety_json={},
            evidence_json={},
        )
        db.add(run)
        db.flush()
        db.add(ValidationStep(validation_run_id=run.id, sequence=1, step_name="Load", status="passed"))
        db.commit()
        saved = db.query(ValidationRun).filter_by(id=run.id).first()
        assert saved is not None
        assert saved.finding.id == finding.id
        assert saved.steps[0].sequence == 1
