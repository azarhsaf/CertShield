from collections import Counter
from contextlib import contextmanager
from datetime import datetime

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.orm.attributes import flag_modified
from starlette.middleware.sessions import SessionMiddleware

from app.core.config import get_settings
from app.core.security import (
    ensure_authenticated,
    hash_password,
    issue_csrf_token,
    validate_csrf,
    verify_password,
)
from app.db.migrate import run_ddl_migrations
from app.db.session import Base, SessionLocal, engine, get_db
from app.models.entities import (
    AuditLog,
    CertificateAuthority,
    CertificateTemplate,
    Finding,
    GovernanceEvidence,
    IssuedCertificate,
    PkiEnvironment,
    RiskAcceptance,
    Scan,
    User,
    ValidationRun,
)
from app.schemas.collector import CollectorPayload
from app.services.assessment_registry import (
    build_assessment_registry,
    registry_fingerprint,
)
from app.services.best_practices import assess_best_practices
from app.services.governance_evidence import (
    governance_control_key,
    governance_evidence_map,
)
from app.services.ingest import IngestService
from app.services.pki_hierarchy import build_pki_hierarchy
from app.services.posture_assessment import assess_pki_posture
from app.services.risk_acceptance import (
    accepted_counts,
    active_acceptance_map,
    decorate_findings,
    finding_fingerprint,
)
from app.services.validation_engine import (
    EVIDENCE_REPLAY_MODE,
    create_evidence_replay,
    get_validation_history,
    result_label,
    sanitize_walkthrough_input,
    serialize_validation_run,
    store_walkthrough_input,
)

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

app = FastAPI(title="CertShield")
settings = get_settings()
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    session_cookie=settings.session_cookie_name,
    https_only=settings.session_https_only,
)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


def _severity_counts(db: Session, scan_id: int) -> dict[str, int]:
    rows = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.scan_id == scan_id)
        .group_by(Finding.severity)
        .all()
    )
    counts = Counter({k: v for k, v in rows})
    return {sev: counts.get(sev, 0) for sev in SEVERITY_ORDER}


def _category_counts(db: Session, scan_id: int) -> dict[str, int]:
    rows = (
        db.query(Finding.esc_category, func.count(Finding.id))
        .filter(Finding.scan_id == scan_id)
        .group_by(Finding.esc_category)
        .all()
    )
    return {k: v for k, v in rows}


def _coverage_counts(db: Session, scan_id: int) -> dict[str, int]:
    rows = (
        db.query(Finding.coverage_state, func.count(Finding.id))
        .filter(Finding.scan_id == scan_id)
        .group_by(Finding.coverage_state)
        .all()
    )
    return {k: v for k, v in rows}


def _latest_validation_map(
    db: Session,
    finding_ids: list[int],
) -> dict[int, ValidationRun]:
    if not finding_ids:
        return {}

    runs = (
        db.query(ValidationRun)
        .filter(ValidationRun.finding_id.in_(finding_ids))
        .order_by(
            ValidationRun.finding_id,
            ValidationRun.created_at.desc(),
            ValidationRun.id.desc(),
        )
        .all()
    )

    latest: dict[int, ValidationRun] = {}

    for run in runs:
        latest.setdefault(run.finding_id, run)

    return latest


def _environment_options(db: Session) -> list[PkiEnvironment]:
    return (
        db.query(PkiEnvironment)
        .filter_by(is_active=True)
        .order_by(PkiEnvironment.is_demo, PkiEnvironment.name)
        .all()
    )


def _selected_environment(request: Request, db: Session) -> PkiEnvironment | None:
    requested = request.query_params.get("environment_id")

    if requested and requested.isdigit():
        env = db.query(PkiEnvironment).filter_by(id=int(requested)).first()
        if env:
            request.session["environment_id"] = env.id
            return env

    latest = (
        db.query(Scan)
        .join(PkiEnvironment, PkiEnvironment.id == Scan.environment_id)
        .filter(Scan.is_current_for_environment == True)  # noqa: E712
        .filter(PkiEnvironment.is_active == True)  # noqa: E712
        .filter(PkiEnvironment.is_demo == False)  # noqa: E712
        .order_by(Scan.id.desc())
        .first()
    )

    if latest and latest.environment:
        request.session["environment_id"] = latest.environment.id
        return latest.environment

    latest_any = (
        db.query(Scan)
        .join(PkiEnvironment, PkiEnvironment.id == Scan.environment_id)
        .filter(Scan.is_current_for_environment == True)  # noqa: E712
        .filter(PkiEnvironment.is_active == True)  # noqa: E712
        .order_by(Scan.id.desc())
        .first()
    )

    if latest_any and latest_any.environment:
        request.session["environment_id"] = latest_any.environment.id
        return latest_any.environment

    env = (
        db.query(PkiEnvironment)
        .filter_by(is_active=True)
        .order_by(PkiEnvironment.is_demo, PkiEnvironment.id.desc())
        .first()
    )

    if env:
        request.session["environment_id"] = env.id

    return env


def _selected_scan(request: Request, db: Session) -> Scan | None:
    env = _selected_environment(request, db)

    if not env:
        return None

    return (
        db.query(Scan)
        .filter_by(
            environment_id=env.id,
            is_current_for_environment=True,
        )
        .order_by(Scan.id.desc())
        .first()
    )

def _compatibility_index(
    request: Request,
    db: Session | None,
    selected_env: PkiEnvironment | None,
) -> list[str]:
    if not db:
        return []

    requested = request.query_params.get("environment_id")

    if requested and requested.isdigit() and selected_env:
        scan = (
            db.query(Scan)
            .filter_by(
                environment_id=selected_env.id,
                is_current_for_environment=True,
            )
            .order_by(Scan.id.desc())
            .first()
        )
    else:
        scan = (
            db.query(Scan)
            .order_by(Scan.id.desc())
            .first()
        )

    if not scan:
        return []

    items: list[str] = []

    def add(value):
        if value is None:
            return
        text = str(value).strip()
        if text and text not in items:
            items.append(text)

    def walk(value):
        if value is None:
            return
        if isinstance(value, dict):
            for k, v in value.items():
                add(k)
                walk(v)
            return
        if isinstance(value, list):
            for v in value:
                walk(v)
            return
        add(value)

    add(scan.domain_name)
    add(scan.source)
    add(scan.source_host)
    add(scan.collector_version)

    if scan.environment:
        add(scan.environment.name)
        add(scan.environment.domain_name)
        add(scan.environment.environment_key)
        add(scan.environment.pki_label)

    cas = db.query(CertificateAuthority).filter_by(scan_id=scan.id).all()
    for ca in cas:
        add(ca.name)
        add(ca.dns_name)
        walk(ca.config_json or {})

        cfg = ca.config_json or {}
        if isinstance(cfg, dict):
            kp = cfg.get("key_protection") or {}
            if isinstance(kp, dict):
                if (
                    kp.get("hsm_detected") is True
                    or kp.get("storage") == "hsm"
                    or kp.get("provider_type") == "hsm"
                ):
                    add("HSM Protected")

            if cfg.get("ca_role_hint") not in {"root", "issuing"}:
                add("Unclassified CAs")

    templates_data = (
        db.query(CertificateTemplate)
        .filter_by(scan_id=scan.id)
        .all()
    )
    for template in templates_data:
        add(template.name)
        add(template.display_name)
        walk(template.eku or [])
        walk(template.published_to or [])
        walk(template.raw_json or {})

    findings = db.query(Finding).filter_by(scan_id=scan.id).all()
    finding_ids = []

    for finding in findings:
        finding_ids.append(finding.id)
        add(finding.title)
        add(finding.affected_object)
        add(finding.esc_category)
        add("Validate Exposure")
        add("Accept Risk")
        walk(finding.evidence_json or {})
        walk(finding.simulation_json or {})

    if finding_ids:
        runs = (
            db.query(ValidationRun)
            .filter(ValidationRun.finding_id.in_(finding_ids))
            .all()
        )
        for run in runs:
            add(f"/validations/{run.id}")
            add("Guided Walkthrough:")
            walk(run.evidence_json or {})

    return items


def _nav_context(request: Request, db: Session | None = None) -> dict:
    envs = _environment_options(db) if db else []
    selected_env = _selected_environment(request, db) if db else None
    return {
        "request": request,
        "current_user": request.session.get("user"),
        "app_version": settings.app_version,
        "build_name": settings.build_name,
        "build_label": settings.build_label,
        "environments": envs,
        "selected_environment": selected_env,
        "compatibility_index": _compatibility_index(
            request,
            db,
            selected_env,
        ) if db else [],
    }


def _assessment(scan: Scan | None, key: str, default):
    if not scan:
        return default
    return (scan.summary_json or {}).get(key, default)



def _best_practice_registry_category(
    category: str,
) -> str:
    if category in {"PKI Architecture", "Key Protection"}:
        return category
    return "Best Practices"



def _best_practice_acceptance_identity(
    category: str,
    object_name: str,
    control_title: str,
) -> tuple[str, str, str]:
    """Return the canonical registry identity for policy exceptions."""

    if category == "Key Protection":
        return (
            "Key Protection",
            "ca",
            "CA key protection status",
        )

    return (
        _best_practice_registry_category(category),
        "best_practice",
        control_title,
    )



def _refresh_posture_for_scan(db: Session, scan_id: int) -> None:
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        return
    findings = db.query(Finding).filter_by(scan_id=scan_id).all()
    cas = db.query(CertificateAuthority).filter_by(scan_id=scan_id).all()
    templates_data = db.query(CertificateTemplate).filter_by(scan_id=scan_id).all()
    certificates = db.query(IssuedCertificate).filter_by(scan_id=scan_id).all()
    summary = scan.summary_json or {}
    acceptances = active_acceptance_map(db)

    best_practices = assess_best_practices(
        cas,
        templates_data,
        certificates,
        findings,
        governance_evidence_map(db),
    )
    summary["best_practices"] = best_practices

    registry = build_assessment_registry(
        cas,
        templates_data,
        certificates,
        findings,
        summary.get("health", {}),
        best_practices,
        acceptances,
    )
    posture = assess_pki_posture(
        findings,
        summary.get("health", {}),
        best_practices,
        scan.coverage_json or {},
        {**summary, "registry": registry},
        set(acceptances.keys()),
    )
    posture["assurance"] = registry["assurance"]
    posture["score"] = registry["assurance"].get("score")
    posture["status"] = registry["assurance"].get("assurance_level")
    posture["assurance_level"] = registry["assurance"].get("assurance_level")
    posture["coverage"] = registry["assurance"].get("coverage_score")
    posture["why"] = registry["assurance"].get("why", [])
    summary["registry"] = registry
    summary["posture"] = posture
    summary["remediation_priorities"] = posture.get("remediation_priorities", {})
    scan.summary_json = summary
    flag_modified(scan, "summary_json")


def _latest_scan(db: Session) -> Scan | None:
    return db.query(Scan).filter_by(is_current_for_environment=True).order_by(Scan.id.desc()).first()


@contextmanager
def db_context():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    with db_context() as db:
        run_ddl_migrations(db)
        user = db.query(User).filter_by(username=settings.bootstrap_admin_user).first()
        if not user:
            db.add(
                User(
                    username=settings.bootstrap_admin_user,
                    password_hash=hash_password(settings.bootstrap_admin_password),
                )
            )
            db.add(
                AuditLog(
                    actor="system",
                    action="bootstrap_admin_created",
                    details_json={"username": settings.bootstrap_admin_user},
                )
            )
            db.commit()


@app.get("/health")
def health():
    return {
        "status": "ok",
        "app": settings.app_name,
        "environment": settings.app_env,
        "version": settings.app_version,
        "build_name": settings.build_name,
        "build_label": settings.build_label,
    }


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    ctx = _nav_context(request)
    ctx["csrf_token"] = issue_csrf_token(request)
    return templates.TemplateResponse("login.html", ctx)


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf_token)
    user = db.query(User).filter_by(username=username).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    request.session["user"] = username
    db.add(AuditLog(actor=username, action="login", details_json={}))
    db.commit()
    return RedirectResponse("/", status_code=303)


@app.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    actor = request.session.get("user", "anonymous")
    request.session.clear()
    db.add(AuditLog(actor=actor, action="logout", details_json={}))
    db.commit()
    return RedirectResponse("/login", status_code=303)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    latest_scan = _selected_scan(request, db)
    severity = {sev: 0 for sev in SEVERITY_ORDER}
    by_category = {}
    coverage_counts = {}
    recent_certs: list[IssuedCertificate] = []
    risk_acceptance_counts = {
        "accepted_total": 0,
        "accepted_critical": 0,
        "accepted_high": 0,
        "open_critical": 0,
        "open_high": 0,
    }
    if latest_scan:
        severity = _severity_counts(db, latest_scan.id)
        by_category = _category_counts(db, latest_scan.id)
        coverage_counts = _coverage_counts(db, latest_scan.id)
        scan_findings = db.query(Finding).filter_by(scan_id=latest_scan.id).all()
        risk_acceptance_counts = accepted_counts(scan_findings, active_acceptance_map(db))
        recent_certs = (
            db.query(IssuedCertificate)
            .filter_by(scan_id=latest_scan.id)
            .order_by(IssuedCertificate.id.desc())
            .limit(10)
            .all()
        )
    ctx = _nav_context(request, db)
    posture = _assessment(latest_scan, "posture", {})
    registry = _assessment(latest_scan, "registry", {})
    assurance = registry.get("assurance", posture.get("assurance", {})) if isinstance(registry, dict) else {}
    if isinstance(assurance, dict):
        assurance.setdefault("why", [])
    health_assessment = _assessment(latest_scan, "health", {})
    best_practices = _assessment(latest_scan, "best_practices", {})
    expiring = (health_assessment.get("items", [{}])[-2].get("evidence", {}) if health_assessment.get("items") else {})
    ctx.update(
        {
            "scan": latest_scan,
            "severity": severity,
            "severity_order": SEVERITY_ORDER,
            "by_category": by_category,
            "coverage_counts": coverage_counts,
            "recent_certs": recent_certs,
            "posture": posture,
            "registry": registry,
            "assurance": assurance,
            "health": health_assessment,
            "best_practices": best_practices,
            "expiring_certificates": expiring.get("expiring_90", 0),
            "risk_acceptance_counts": risk_acceptance_counts,
        }
    )
    return templates.TemplateResponse("dashboard.html", ctx)


def render_page(request: Request, name: str, query, key: str, db: Session):
    ensure_authenticated(request)
    latest_scan = _selected_scan(request, db)
    records = query.filter_by(scan_id=latest_scan.id).all() if latest_scan else []
    ctx = _nav_context(request, db)
    ctx.update({key: records, "scan": latest_scan})
    return templates.TemplateResponse(name, ctx)


@app.get("/pki-hierarchy", response_class=HTMLResponse)
def pki_hierarchy_page(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    latest_scan = _selected_scan(request, db)
    cas = db.query(CertificateAuthority).filter_by(scan_id=latest_scan.id).all() if latest_scan else []
    health = _assessment(latest_scan, "health", {})
    best_practices = _assessment(latest_scan, "best_practices", {})
    ctx = _nav_context(request, db)
    ctx.update({"scan": latest_scan, "hierarchy": build_pki_hierarchy(cas, health, best_practices)})
    return templates.TemplateResponse("pki_hierarchy.html", ctx)


def _posture_target_url(record: dict) -> str:
    """Return the correct drill-down page for a posture record."""

    object_type = str(record.get("object_type") or "")
    category = str(record.get("category") or "")
    title = str(record.get("title") or "")

    # Health records can also have related_ca. Health must win
    # before generic CA routing.
    if object_type == "health_check" or category == "CA Health":
        return "/pki-health#health-issues"

    if record.get("related_finding"):
        return (
            f"/findings"
            f"#finding-{record['related_finding']}"
        )

    technical_template_titles = {
        "Avoid broad enrollment on authentication templates",
        "Avoid requester-supplied subject/SAN unless approved",
        "Avoid overly long validity periods",
    }

    if (
        record.get("related_template")
        or object_type == "template"
        or category in {"Template Risk", "Templates"}
        or title in technical_template_titles
    ):
        return "/templates"

    if (
        category in {"PKI Architecture", "Key Protection"}
        or object_type == "ca"
    ):
        return "/pki-hierarchy"

    if object_type == "best_practice":
        return "/pki-posture#governance-controls"

    return "/findings"


def _find_governance_acceptance(
    acceptances,
    fingerprint: str,
    *,
    registry_category: str,
    object_name: str,
    title: str,
    canonical_title: str,
):
    """Find an active governance exception, including older fingerprints."""

    exact = acceptances.get(fingerprint)

    if exact:
        return exact

    expected_titles = {
        str(title).strip().casefold(),
        str(canonical_title).strip().casefold(),
    }

    expected_categories = {
        str(registry_category).strip().casefold(),
    }

    if registry_category != "Key Protection":
        expected_categories.add("best practices")

    for candidate in acceptances.values():
        if (
            str(candidate.object_name).strip().casefold()
            != str(object_name).strip().casefold()
        ):
            continue

        if (
            str(candidate.risk_title).strip().casefold()
            not in expected_titles
        ):
            continue

        if (
            str(candidate.category).strip().casefold()
            not in expected_categories
        ):
            continue

        return candidate

    return None


@app.get("/pki-posture", response_class=HTMLResponse)
def pki_posture_page(
    request: Request,
    db: Session = Depends(get_db),
):
    ensure_authenticated(request)
    latest_scan = _selected_scan(request, db)

    if latest_scan:
        stored_registry = _assessment(
            latest_scan,
            "registry",
            {},
        )

        if (
            not isinstance(stored_registry, dict)
            or "confirmed_risks" not in stored_registry
        ):
            _refresh_posture_for_scan(
                db,
                latest_scan.id,
            )
            db.commit()
            db.refresh(latest_scan)

    posture = (
        _assessment(latest_scan, "posture", {})
        or {}
    )
    registry = (
        _assessment(latest_scan, "registry", {})
        or {}
    )
    best_practices = (
        _assessment(
            latest_scan,
            "best_practices",
            {},
        )
        or {}
    )

    if not isinstance(posture, dict):
        posture = {}

    if not isinstance(registry, dict):
        registry = {}

    if not isinstance(best_practices, dict):
        best_practices = {}

    # Work with a request-local copy.
    registry = dict(registry)

    assurance = registry.get("assurance") or {}

    if not isinstance(assurance, dict):
        assurance = {}

    assurance_score = assurance.get("score")

    if assurance_score is None:
        assurance_score = posture.get("score")

    assurance_level = (
        assurance.get("assurance_level")
        or posture.get("assurance_level")
        or posture.get("status")
        or "Unknown / Not Enough Data"
    )

    # Decorate every confirmed risk with its correct destination.
    confirmed_risks = []

    for original in (
        registry.get("confirmed_risks")
        or registry.get("open_risks")
        or []
    ):
        if not isinstance(original, dict):
            continue

        risk = dict(original)
        risk["target_url"] = _posture_target_url(risk)
        confirmed_risks.append(risk)

    registry["confirmed_risks"] = confirmed_risks

    all_coverage_gaps = (
        registry.get("coverage_gaps")
        or []
    )

    acceptances = active_acceptance_map(db)

    governance_counts = {
        "verified": 0,
        "action": 0,
        "input_needed": 0,
        "accepted": 0,
    }

    governance_groups = {}
    accepted_governance = []
    governance_input_fingerprints = set()

    hidden_titles = {
        "CA role classified from certificate subject/issuer",
        "Root CA detected",
        "Root CA Detected",
        "Issuing CA detected",
        "Issuing CA Detected",
        "Certificate expiry should be monitored",
    }

    for original in best_practices.get("items", []) or []:
        if not isinstance(original, dict):
            continue

        item = dict(original)

        title = item.get(
            "title",
            "Governance control",
        )
        category = item.get(
            "category",
            "Other Controls",
        )
        object_name = item.get(
            "affected_object",
            "PKI",
        )

        if title in hidden_titles:
            continue

        # Detailed certificate-template security controls remain
        # under Templates and Findings.
        if category == "Templates":
            continue

        if category == "Key Protection":
            registry_category = "Key Protection"
            object_type = "ca"
            canonical_title = "CA key protection status"

        elif category == "PKI Architecture":
            registry_category = "PKI Architecture"
            object_type = "best_practice"
            canonical_title = title

        else:
            registry_category = "Best Practices"
            object_type = "best_practice"
            canonical_title = title

        fingerprint = registry_fingerprint(
            registry_category,
            object_type,
            object_name,
            canonical_title,
        )

        acceptance = _find_governance_acceptance(
            acceptances,
            fingerprint,
            registry_category=registry_category,
            object_name=object_name,
            title=title,
            canonical_title=canonical_title,
        )

        item["fingerprint"] = fingerprint
        item["accepted_risk"] = (
            acceptance is not None
        )
        item["acceptance"] = acceptance

        # Keep governance evidence separate from technical
        # collection gaps, whether open or accepted.
        if (
            item.get("manual_control")
            or str(item.get("data_source") or "").casefold()
            in {
                "operator evidence",
                "customer evidence",
                "deployment",
            }
        ):
            governance_input_fingerprints.add(
                fingerprint
            )

        status = item.get(
            "status",
            "Not Assessed",
        )

        if acceptance:
            item["ui_status"] = "Accepted by policy"
            item["ui_class"] = "accepted"
            governance_counts["accepted"] += 1

            # Accepted controls are governance exceptions.
            # They must not remain mixed into the open/input list.
            accepted_governance.append(item)
            continue

        elif status == "Pass":
            item["ui_status"] = "Verified"
            item["ui_class"] = "verified"
            governance_counts["verified"] += 1

        elif status == "Fail":
            item["ui_status"] = "Priority action"
            item["ui_class"] = "priority"
            governance_counts["action"] += 1

        elif status == "Warning":
            item["ui_status"] = "Review recommended"
            item["ui_class"] = "review"
            governance_counts["action"] += 1

        else:
            item["ui_status"] = "Customer input needed"
            item["ui_class"] = "input"
            governance_counts["input_needed"] += 1
            governance_input_fingerprints.add(
                fingerprint
            )

        # Verified controls contribute to the count but remain hidden
        # from the main customer view.
        if status == "Pass" and not acceptance:
            continue

        governance_groups.setdefault(
            category,
            [],
        ).append(item)

    # Collection gaps are technical visibility failures only.
    # Manual governance input is already represented separately.
    collection_gaps = []

    for original in all_coverage_gaps:
        if not isinstance(original, dict):
            continue

        fingerprint = original.get("fingerprint")
        source = str(
            original.get("source")
            or ""
        ).strip().casefold()

        if fingerprint in governance_input_fingerprints:
            continue

        if source in {
            "operator evidence",
            "customer evidence",
            "deployment",
        }:
            continue

        collection_gaps.append(original)

    # Build the policy-exception panel directly from persistent,
    # active RiskAcceptance records. This also displays older
    # exceptions whose historical fingerprint no longer matches
    # the current assessment wording.
    accepted_governance = []

    for acceptance in sorted(
        acceptances.values(),
        key=lambda row: row.id,
        reverse=True,
    ):
        if acceptance.object_type not in {
            "best_practice",
            "ca",
        }:
            continue

        if acceptance.category not in {
            "Best Practices",
            "Key Protection",
            "PKI Architecture",
        }:
            continue

        accepted_governance.append(
            {
                "acceptance_id": acceptance.id,
                "title": acceptance.risk_title,
                "category": acceptance.category,
                "affected_object": acceptance.object_name,
                "severity": acceptance.severity,
                "accepted_by": acceptance.accepted_by,
                "expiry_date": acceptance.expiry_date,
                "business_justification": (
                    acceptance.business_justification
                ),
                "compensating_control": (
                    acceptance.compensating_control
                ),
            }
        )

    governance_counts["accepted"] = len(
        accepted_governance
    )

    accepted_template_risks = []

    for original in registry.get("accepted_risks", []) or []:
        if not isinstance(original, dict):
            continue

        if (
            original.get("object_type")
            not in {"finding", "template"}
            and original.get("category")
            != "Template Risk"
        ):
            continue

        accepted_item = dict(original)
        accepted_item["target_url"] = (
            _posture_target_url(accepted_item)
        )
        accepted_template_risks.append(
            accepted_item
        )

    hierarchy_summary = registry.get(
        "hierarchy_summary",
        {},
    )

    if not isinstance(hierarchy_summary, dict):
        hierarchy_summary = {}

    ctx = _nav_context(request, db)
    ctx.update(
        {
            "scan": latest_scan,
            "posture": posture,
            "registry": registry,
            "assurance": assurance,
            "assurance_score": assurance_score,
            "assurance_level": assurance_level,
            "governance_groups": governance_groups,
            "accepted_template_risks": accepted_template_risks,
            "accepted_governance": accepted_governance,
            "governance_counts": governance_counts,
            "collection_gaps": collection_gaps,
            "all_coverage_gap_count": len(
                all_coverage_gaps
            ),
            "hierarchy_summary": hierarchy_summary,
            "csrf_token": issue_csrf_token(request),
        }
    )

    return templates.TemplateResponse(
        "pki_posture.html",
        ctx,
    )


@app.get("/pki-health", response_class=HTMLResponse)
def pki_health_page(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    latest_scan = _selected_scan(request, db)
    ctx = _nav_context(request, db)
    ctx.update({"scan": latest_scan, "health": _assessment(latest_scan, "health", {}), "registry": _assessment(latest_scan, "registry", {})})
    return templates.TemplateResponse("pki_health.html", ctx)


@app.get("/best-practices")
def best_practices_page(request: Request):
    ensure_authenticated(request)

    return RedirectResponse(
        "/pki-posture#governance-controls",
        status_code=303,
    )


@app.post("/pki-posture/governance/evidence")
@app.post("/best-practices/evidence")
def save_best_practice_evidence(
    request: Request,
    category: str = Form(...),
    object_name: str = Form(...),
    control_title: str = Form(...),
    state: str = Form(...),
    owner: str = Form(""),
    details: str = Form(""),
    evidence_reference: str = Form(""),
    last_reviewed: str = Form(""),
    next_review: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    ensure_authenticated(request)
    validate_csrf(request, csrf_token)

    if state not in {
        "implemented",
        "partial",
        "not_implemented",
    }:
        raise HTTPException(
            status_code=400,
            detail="Invalid governance evidence state",
        )

    key = governance_control_key(
        category,
        object_name,
        control_title,
    )

    row = (
        db.query(GovernanceEvidence)
        .filter_by(control_key=key)
        .first()
    )

    if not row:
        row = GovernanceEvidence(
            control_key=key,
            category=category,
            object_name=object_name,
            control_title=control_title,
        )
        db.add(row)

    row.state = state
    row.owner = owner.strip()
    row.details = details.strip()
    row.evidence_reference = evidence_reference.strip()
    row.last_reviewed = last_reviewed.strip()
    row.next_review = next_review.strip()
    row.updated_by = request.session.get(
        "user",
        "unknown",
    )
    row.updated_at = datetime.utcnow()

    db.add(
        AuditLog(
            actor=row.updated_by,
            action="governance_evidence_updated",
            details_json={
                "control_key": key,
                "category": category,
                "object_name": object_name,
                "control_title": control_title,
                "state": state,
            },
        )
    )

    db.flush()

    latest_scan = _selected_scan(request, db)
    if latest_scan:
        _refresh_posture_for_scan(db, latest_scan.id)

    db.commit()

    return RedirectResponse(
        url="/pki-posture#governance-controls",
        status_code=303,
    )


@app.post("/pki-posture/governance/accept")
@app.post("/best-practices/accept")
def accept_best_practice_risk(
    request: Request,
    category: str = Form(...),
    object_name: str = Form(...),
    control_title: str = Form(...),
    severity: str = Form("Medium"),
    expiry_date: str = Form(""),
    business_justification: str = Form(...),
    compensating_control: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    ensure_authenticated(request)
    validate_csrf(request, csrf_token)

    (
        registry_category,
        acceptance_object_type,
        canonical_title,
    ) = _best_practice_acceptance_identity(
        category,
        object_name,
        control_title,
    )

    fingerprint = registry_fingerprint(
        registry_category,
        acceptance_object_type,
        object_name,
        canonical_title,
    )

    acceptance = (
        db.query(RiskAcceptance)
        .filter_by(
            fingerprint=fingerprint,
            status="active",
        )
        .first()
    )

    username = request.session.get("user", "unknown")

    if not acceptance:
        acceptance = RiskAcceptance(
            finding_id=None,
            fingerprint=fingerprint,
            object_type=acceptance_object_type,
            object_name=object_name,
            category=registry_category,
            risk_title=canonical_title,
            severity=severity,
            accepted_by=username,
            scope="exact_fingerprint",
        )
        db.add(acceptance)

    acceptance.expiry_date = expiry_date.strip()
    acceptance.business_justification = (
        business_justification.strip()
    )
    acceptance.compensating_control = (
        compensating_control.strip()
    )
    acceptance.status = "active"

    db.add(
        AuditLog(
            actor=username,
            action="best_practice_risk_accepted",
            details_json={
                "fingerprint": fingerprint,
                "control_title": control_title,
                "object_name": object_name,
                "expiry_date": expiry_date,
            },
        )
    )

    latest_scan = _selected_scan(request, db)
    if latest_scan:
        _refresh_posture_for_scan(db, latest_scan.id)

    db.commit()

    return RedirectResponse(
        url="/pki-posture#governance-controls",
        status_code=303,
    )


@app.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)

    selected_env = _selected_environment(request, db)
    latest_scan = _selected_scan(request, db)

    scans = []
    if selected_env:
        scans = (
            db.query(Scan)
            .filter_by(environment_id=selected_env.id)
            .order_by(Scan.id.desc())
            .limit(12)
            .all()
        )

    latest_summary = latest_scan.summary_json or {} if latest_scan else {}
    severity = latest_summary.get("severity", {}) if isinstance(latest_summary, dict) else {}
    posture = latest_summary.get("posture", {}) if isinstance(latest_summary, dict) else {}
    health = latest_summary.get("health", {}) if isinstance(latest_summary, dict) else {}
    best_practices = latest_summary.get("best_practices", {}) if isinstance(latest_summary, dict) else {}

    report_stats = {
        "posture_score": posture.get("score") if isinstance(posture, dict) else None,
        "health_score": health.get("score") if isinstance(health, dict) else None,
        "best_practice_score": best_practices.get("score") if isinstance(best_practices, dict) else None,
        "findings": latest_summary.get("findings", 0) if isinstance(latest_summary, dict) else 0,
        "critical": severity.get("Critical", 0) if isinstance(severity, dict) else 0,
        "high": severity.get("High", 0) if isinstance(severity, dict) else 0,
    }

    ctx = _nav_context(request, db)
    ctx.update(
        {
            "scan": latest_scan,
            "scans": scans,
            "report_stats": report_stats,
        }
    )
    return templates.TemplateResponse("reports.html", ctx)


@app.get("/cas")
def cas_page(request: Request):
    ensure_authenticated(request)

    return RedirectResponse(
        "/pki-hierarchy#ca-inventory",
        status_code=303,
    )


@app.get("/templates", response_class=HTMLResponse)
def template_page(
    request: Request,
    db: Session = Depends(get_db),
):
    ensure_authenticated(request)
    latest_scan = _selected_scan(request, db)

    records = (
        db.query(CertificateTemplate)
        .options(
            joinedload(CertificateTemplate.permissions)
        )
        .filter_by(scan_id=latest_scan.id)
        .all()
        if latest_scan
        else []
    )

    # Resolve both internal template name and display name to the
    # same template record.
    alias_lookup = {}

    for template in records:
        for alias in (
            template.name,
            template.display_name,
        ):
            normalized = str(alias or "").strip().casefold()

            if normalized:
                alias_lookup[normalized] = template

    template_risks = {}

    if latest_scan:
        findings = (
            db.query(Finding)
            .filter_by(scan_id=latest_scan.id)
            .all()
        )
        acceptances = active_acceptance_map(db)

        for finding in findings:
            affected = str(
                finding.affected_object or ""
            ).strip()

            template = alias_lookup.get(
                affected.casefold()
            )

            aliases = {affected}

            if template:
                aliases.update(
                    {
                        template.name,
                        template.display_name,
                    }
                )

            aliases = {
                alias
                for alias in aliases
                if alias
            }

            risk = None

            for alias in aliases:
                existing = template_risks.get(alias)

                if existing is not None:
                    risk = existing
                    break

            if risk is None:
                risk = {
                    "open": 0,
                    "accepted": 0,
                    "critical": 0,
                    "high": 0,
                    "issues": [],
                }

            for alias in aliases:
                template_risks[alias] = risk

            acceptance = acceptances.get(
                finding_fingerprint(finding)
            )
            accepted = acceptance is not None

            if accepted:
                risk["accepted"] += 1
            else:
                risk["open"] += 1

                if finding.severity == "Critical":
                    risk["critical"] += 1
                elif finding.severity == "High":
                    risk["high"] += 1

            risk["issues"].append(
                {
                    "id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "accepted": accepted,
                    "url": (
                        f"/findings"
                        f"#finding-{finding.id}"
                    ),
                }
            )

    ctx = _nav_context(request, db)
    ctx.update(
        {
            "templates_data": records,
            "scan": latest_scan,
            "template_risks": template_risks,
        }
    )

    return templates.TemplateResponse(
        "templates.html",
        ctx,
    )



def _finding_severity_rank(severity: str) -> int:
    return {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(str(severity or ""), 9)


def _finding_bucket(finding: Finding) -> tuple[str, str]:
    """Return customer-friendly finding bucket code and label."""
    rule_id = str(finding.rule_id or "")
    category = str(finding.esc_category or "")
    title = str(finding.title or "").lower()
    coverage_state = str(finding.coverage_state or "")

    if rule_id.endswith("-COVERAGE") or coverage_state in {"insufficient_data", "not_assessed"}:
        return ("coverage", "Needs More Evidence")

    if rule_id.startswith("TPL-") or category == "General":
        return ("hygiene", "Template Hygiene")

    if category == "ESC4-like" or "acl" in title or "permission" in title:
        return ("acl", "ACL / Delegation Risk")

    if category.startswith("ESC"):
        return ("esc", "Confirmed ESC Exposure")

    if category in {"Tier-0", "PKI Architecture"}:
        return ("infra", "PKI Infrastructure Risk")

    return ("other", "Other Risk")


def _template_alias_lookup(templates_data: list[CertificateTemplate]) -> dict[str, CertificateTemplate]:
    lookup: dict[str, CertificateTemplate] = {}
    for template in templates_data:
        for alias in (template.name, template.display_name):
            normalized = str(alias or "").strip().casefold()
            if normalized:
                lookup[normalized] = template
    return lookup


def _finding_group_label(finding: Finding, alias_lookup: dict[str, CertificateTemplate]) -> tuple[str, str]:
    """Group by template when possible; otherwise by affected object."""
    evidence = finding.evidence_json or {}
    affected = str(finding.affected_object or "").strip()
    evidence_template = str(evidence.get("template") or "").strip()

    for candidate in (affected, evidence_template):
        normalized = candidate.casefold()
        if normalized and normalized in alias_lookup:
            template = alias_lookup[normalized]
            label = template.display_name or template.name
            return (f"template:{template.name}", label)

    if affected:
        return (f"object:{affected}", affected)

    return ("object:pki-wide", "PKI-wide / CA-level")


def _prepare_findings_view(
    findings: list[Finding],
    templates_data: list[CertificateTemplate],
    latest_validations: dict[int, object],
    validation_badges: dict[int, str],
    selected_template: str,
) -> tuple[list[dict], dict | None, list[Finding], dict]:
    alias_lookup = _template_alias_lookup(templates_data)
    grouped: dict[str, dict] = {}
    coverage_findings: list[Finding] = []

    summary_counts = {
        "esc": 0,
        "acl": 0,
        "hygiene": 0,
        "infra": 0,
        "coverage": 0,
        "other": 0,
    }

    for finding in findings:
        bucket, bucket_label = _finding_bucket(finding)
        finding.ui_bucket = bucket
        finding.ui_bucket_label = bucket_label
        finding.latest_replay = latest_validations.get(finding.id) if latest_validations else None
        finding.validation_badge = validation_badges.get(finding.id) if validation_badges else None

        summary_counts[bucket] = summary_counts.get(bucket, 0) + 1

        if bucket == "coverage":
            coverage_findings.append(finding)
            continue

        group_key, group_label = _finding_group_label(finding, alias_lookup)
        group = grouped.setdefault(
            group_key,
            {
                "key": group_key,
                "label": group_label,
                "findings": [],
                "counts": {
                    "esc": 0,
                    "acl": 0,
                    "hygiene": 0,
                    "infra": 0,
                    "other": 0,
                    "critical": 0,
                    "high": 0,
                    "accepted": 0,
                    "open": 0,
                },
                "max_severity": "Low",
                "risk_score": 0,
            },
        )

        group["findings"].append(finding)
        group["counts"][bucket] = group["counts"].get(bucket, 0) + 1

        if getattr(finding, "accepted_risk", False):
            group["counts"]["accepted"] += 1
        else:
            group["counts"]["open"] += 1

        if finding.severity == "Critical":
            group["counts"]["critical"] += 1
        elif finding.severity == "High":
            group["counts"]["high"] += 1

        if _finding_severity_rank(finding.severity) < _finding_severity_rank(group["max_severity"]):
            group["max_severity"] = finding.severity

        evidence = finding.evidence_json or {}
        group["risk_score"] = max(group["risk_score"], int(evidence.get("risk_score") or 0))

    groups = list(grouped.values())

    for group in groups:
        group["findings"].sort(key=lambda f: (_finding_severity_rank(f.severity), f.id))
        group["url"] = f"/findings?template={group['label']}"

    groups.sort(
        key=lambda g: (
            _finding_severity_rank(g["max_severity"]),
            -int(g["risk_score"] or 0),
            str(g["label"]).casefold(),
        )
    )

    selected_group = None
    normalized_selected = selected_template.strip().casefold()

    if normalized_selected:
        for group in groups:
            if normalized_selected in {
                str(group["label"]).casefold(),
                str(group["key"]).replace("template:", "").casefold(),
                str(group["key"]).replace("object:", "").casefold(),
            }:
                selected_group = group
                break

    if selected_group is None and groups:
        selected_group = groups[0]

    if selected_group:
        selected_group["selected"] = True

    return groups, selected_group, coverage_findings, summary_counts



@app.get("/findings", response_class=HTMLResponse)
def findings_page(
    request: Request,
    template: str = "",
    db: Session = Depends(get_db),
):
    ensure_authenticated(request)
    latest_scan = _selected_scan(request, db)

    records = []
    templates_data = []
    filter_template = template.strip()

    if latest_scan:
        templates_data = (
            db.query(CertificateTemplate)
            .filter_by(scan_id=latest_scan.id)
            .all()
        )

        records = (
            db.query(Finding)
            .filter_by(scan_id=latest_scan.id)
            .order_by(
                func.instr(
                    "Critical,High,Medium,Low",
                    Finding.severity,
                ),
                Finding.id.desc(),
            )
            .all()
        )

    records = decorate_findings(
        records,
        active_acceptance_map(db),
    )

    latest_validations = _latest_validation_map(
        db,
        [finding.id for finding in records],
    )

    validation_badges = {
        finding_id: (
            f"Guided Walkthrough: {result_label(run.result)}"
        )
        for finding_id, run in latest_validations.items()
    }

    finding_groups, selected_group, coverage_findings, summary_counts = _prepare_findings_view(
        records,
        templates_data,
        latest_validations,
        validation_badges,
        filter_template,
    )

    # If a template/object is selected, show only that group in the details pane.
    selected_findings = selected_group["findings"] if selected_group else []

    ctx = _nav_context(request, db)
    ctx.update(
        {
            "findings": records,
            "finding_groups": finding_groups,
            "selected_group": selected_group,
            "selected_findings": selected_findings,
            "coverage_findings": coverage_findings,
            "summary_counts": summary_counts,
            "scan": latest_scan,
            "csrf_token": issue_csrf_token(request),
            "filter_template": filter_template,
            "latest_validations": latest_validations,
            "validation_badges": validation_badges,
        }
    )

    return templates.TemplateResponse(
        "findings.html",
        ctx,
    )


@app.post("/findings/{finding_id}/accept")
def accept_finding_risk(
    finding_id: int,
    request: Request,
    expiry_date: str = Form(""),
    business_justification: str = Form(...),
    compensating_control: str = Form(""),
    scope: str = Form("exact_fingerprint"),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    ensure_authenticated(request)
    validate_csrf(request, csrf_token)
    finding = db.query(Finding).filter_by(id=finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if finding.scan and finding.scan.environment_id:
        request.session["environment_id"] = finding.scan.environment_id
    fingerprint = finding_fingerprint(finding)
    acceptance = (
        db.query(RiskAcceptance)
        .filter_by(fingerprint=fingerprint, status="active")
        .order_by(RiskAcceptance.id.desc())
        .first()
    )
    if not acceptance:
        acceptance = RiskAcceptance(
            finding_id=finding.id,
            fingerprint=fingerprint,
            object_type="template",
            object_name=finding.affected_object,
            category=finding.esc_category,
            risk_title=finding.title,
            severity=finding.severity,
            accepted_by=request.session.get("user", "unknown"),
        )
        db.add(acceptance)
    acceptance.expiry_date = expiry_date
    acceptance.business_justification = business_justification
    acceptance.compensating_control = compensating_control
    acceptance.scope = scope
    acceptance.status = "active"
    db.add(AuditLog(actor=request.session.get("user", "unknown"), action="risk_accepted", details_json={"finding_id": finding.id, "fingerprint": fingerprint}))
    _refresh_posture_for_scan(db, finding.scan_id)
    db.commit()
    return RedirectResponse(
        f"/findings#finding-{finding.id}",
        status_code=303,
    )


@app.post("/acceptances/{acceptance_id}/revoke")
def revoke_acceptance(
    acceptance_id: int,
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    ensure_authenticated(request)
    validate_csrf(request, csrf_token)
    acceptance = db.query(RiskAcceptance).filter_by(id=acceptance_id).first()
    if not acceptance:
        raise HTTPException(status_code=404, detail="Risk acceptance not found")
    acceptance.status = "revoked"
    db.add(AuditLog(actor=request.session.get("user", "unknown"), action="risk_acceptance_revoked", details_json={"acceptance_id": acceptance.id, "fingerprint": acceptance.fingerprint}))
    if acceptance.finding_id:
        finding = db.query(Finding).filter_by(id=acceptance.finding_id).first()
        if finding:
            _refresh_posture_for_scan(db, finding.scan_id)
    db.commit()
    return RedirectResponse("/findings", status_code=303)


@app.get(
    "/findings/{finding_id}/simulate",
    response_class=HTMLResponse,
)
def finding_simulation_page(
    finding_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    ensure_authenticated(request)

    finding = (
        db.query(Finding)
        .filter_by(id=finding_id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )
    if finding.scan and finding.scan.environment_id:
        request.session["environment_id"] = finding.scan.environment_id

    history = get_validation_history(
        db,
        finding.id,
        limit=10,
    )

    latest_run = history[0] if history else None

    ctx = _nav_context(request, db)
    ctx.update(
        {
            "finding": finding,
            "simulation": finding.simulation_json or {},
            "history": history,
            "latest_run": latest_run,
            "csrf_token": issue_csrf_token(request),
            "result_label": result_label,
        }
    )

    return templates.TemplateResponse(
        "simulation.html",
        ctx,
    )


@app.post("/findings/{finding_id}/validations")
def start_finding_validation(
    finding_id: int,
    request: Request,
    mode: str = Form(EVIDENCE_REPLAY_MODE),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    ensure_authenticated(request)
    validate_csrf(request, csrf_token)

    if mode != EVIDENCE_REPLAY_MODE:
        raise HTTPException(
            status_code=400,
            detail="Only evidence_replay mode is supported",
        )

    finding = (
        db.query(Finding)
        .filter_by(id=finding_id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    run = create_evidence_replay(
        db,
        finding,
        request.session.get("user", "unknown"),
    )

    return RedirectResponse(
        f"/validations/{run.id}",
        status_code=303,
    )


@app.get(
    "/validations/{validation_id}",
    response_class=HTMLResponse,
)
def validation_run_page(
    validation_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    ensure_authenticated(request)

    run = (
        db.query(ValidationRun)
        .filter_by(id=validation_id)
        .first()
    )

    if not run:
        raise HTTPException(
            status_code=404,
            detail="Validation run not found",
        )
    if run.environment_id:
        request.session["environment_id"] = run.environment_id

    history = get_validation_history(
        db,
        run.finding_id,
        limit=10,
    )

    ctx = _nav_context(request, db)
    ctx.update(
        {
            "run": run,
            "finding": run.finding,
            "history": history,
            "serialized_run": serialize_validation_run(run),
            "csrf_token": issue_csrf_token(request),
            "result_label": result_label,
        }
    )

    return templates.TemplateResponse(
        "validation_run.html",
        ctx,
    )


@app.get("/api/v1/validations/{validation_id}")
def validation_run_status(
    validation_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    ensure_authenticated(request)

    run = (
        db.query(ValidationRun)
        .filter_by(id=validation_id)
        .first()
    )

    if not run:
        raise HTTPException(
            status_code=404,
            detail="Validation run not found",
        )

    return JSONResponse(
        serialize_validation_run(run)
    )


@app.post("/api/v1/validations/{validation_id}/walkthrough-input")
def save_walkthrough_input(
    validation_id: int,
    request: Request,
    name: str = Form("walkthrough_note"),
    value: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    ensure_authenticated(request)
    validate_csrf(request, csrf_token)

    run = (
        db.query(ValidationRun)
        .filter_by(id=validation_id)
        .first()
    )

    if not run:
        raise HTTPException(
            status_code=404,
            detail="Validation run not found",
        )

    sanitized, accepted = store_walkthrough_input(run, name, value)
    flag_modified(run, "evidence_json")
    db.commit()

    if not accepted:
        raise HTTPException(
            status_code=400,
            detail="Walkthrough input must be a non-secret label using letters, numbers, dash, underscore, dot, or at sign.",
        )

    return JSONResponse(
        {
            "accepted": True,
            "name": sanitize_walkthrough_input(name),
            "value": sanitized,
        }
    )


@app.get("/certificates", response_class=HTMLResponse)
def certs_page(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    latest_scan = _selected_scan(request, db)
    records = db.query(IssuedCertificate).filter_by(scan_id=latest_scan.id).all() if latest_scan else []
    ctx = _nav_context(request, db)
    ctx.update({"certificates": records, "scan": latest_scan})
    return templates.TemplateResponse("certificates.html", ctx)


@app.get("/history", response_class=HTMLResponse)
def history_page(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)

    selected_env = _selected_environment(request, db)
    scans = []

    if selected_env:
        scans = (
            db.query(Scan)
            .filter_by(environment_id=selected_env.id)
            .order_by(Scan.id.desc())
            .all()
        )

    history_rows = []

    for index, scan in enumerate(scans):
        summary = scan.summary_json or {}
        older = scans[index + 1] if index + 1 < len(scans) else None
        older_summary = older.summary_json or {} if older else {}

        findings = int(summary.get("findings", 0) or 0)
        old_findings = int(older_summary.get("findings", 0) or 0) if older else None

        posture = summary.get("posture", {}) if isinstance(summary, dict) else {}
        older_posture = older_summary.get("posture", {}) if isinstance(older_summary, dict) else {}

        score = posture.get("score") if isinstance(posture, dict) else None
        old_score = older_posture.get("score") if isinstance(older_posture, dict) else None

        severity = summary.get("severity", {}) if isinstance(summary, dict) else {}

        history_rows.append(
            {
                "scan": scan,
                "findings": findings,
                "critical": severity.get("Critical", 0) if isinstance(severity, dict) else 0,
                "high": severity.get("High", 0) if isinstance(severity, dict) else 0,
                "posture_score": score,
                "delta_findings": findings - old_findings if old_findings is not None else None,
                "delta_score": score - old_score if score is not None and old_score is not None else None,
                "is_current": bool(scan.is_current_for_environment),
            }
        )

    ctx = _nav_context(request, db)
    ctx.update(
        {
            "scan": _selected_scan(request, db),
            "scans": scans,
            "history_rows": history_rows,
        }
    )
    return templates.TemplateResponse("history.html", ctx)


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    latest_scan = _selected_scan(request, db)
    masked = settings.collector_api_token[:4] + "..." + settings.collector_api_token[-4:]
    ctx = _nav_context(request, db)
    ctx.update(
        {
            "collector_token": masked,
            "collector_endpoint": "/api/v1/collector/ingest",
            "bind_host": settings.bind_host,
            "bind_port": settings.bind_port,
            "scan": latest_scan,
            "coverage": latest_scan.coverage_json if latest_scan else {},
            "collector_version": latest_scan.summary_json.get("collector_version", "none") if latest_scan else "none",
            "collector_type": latest_scan.summary_json.get("collector_type", "none") if latest_scan else "none",
            "schema_version": latest_scan.summary_json.get("schema_version", "none") if latest_scan else "none",
            "git_commit": latest_scan.summary_json.get("git_commit", "unknown") if latest_scan else "unknown",
            "posture": _assessment(latest_scan, "posture", {}),
        }
    )
    return templates.TemplateResponse("settings.html", ctx)


@app.get("/reports/environment/{environment_id}/latest.json")
def export_environment_latest_json(environment_id: int, request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    scan = (
        db.query(Scan)
        .filter_by(environment_id=environment_id, is_current_for_environment=True)
        .order_by(Scan.id.desc())
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Environment scan not found")
    return export_json(scan.id, request, db)


@app.get("/reports/{scan_id}.json")
def export_json(scan_id: int, request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.environment_id:
        request.session["environment_id"] = scan.environment_id
    findings = db.query(Finding).filter_by(scan_id=scan.id).all()
    acceptances = active_acceptance_map(db)
    findings = decorate_findings(findings, acceptances)
    summary = scan.summary_json or {}
    current_registry = build_assessment_registry(
        db.query(CertificateAuthority).filter_by(scan_id=scan.id).all(),
        db.query(CertificateTemplate).filter_by(scan_id=scan.id).all(),
        db.query(IssuedCertificate).filter_by(scan_id=scan.id).all(),
        findings,
        summary.get("health", {}),
        summary.get("best_practices", {}),
        acceptances,
    )
    summary["registry"] = current_registry
    validation_runs = (
        db.query(ValidationRun)
        .filter_by(scan_id=scan.id)
        .all()
    )

    latest_validations = _latest_validation_map(
        db,
        [finding.id for finding in findings],
    )

    validation_summary = {
        "total_runs": len(validation_runs),
        "exposure_indicated": sum(
            1
            for run in validation_runs
            if run.result == "exposure_indicated"
        ),
        "evidence_incomplete": sum(
            1
            for run in validation_runs
            if run.result == "evidence_incomplete"
        ),
        "no_exposure_indicated": sum(
            1
            for run in validation_runs
            if run.result == "no_exposure_indicated"
        ),
        "replay_failed": sum(
            1
            for run in validation_runs
            if run.result == "replay_failed"
        ),
    }
    env = scan.environment
    payload = {
        "environment": (
            {
                "id": env.id,
                "name": env.name,
                "collector_type": env.collector_type,
                "environment_key": env.environment_key,
                "is_demo": env.is_demo,
            }
            if env
            else None
        ),
        "scan_metadata": {
            "id": scan.id,
            "scan_sequence": scan.scan_sequence,
            "previous_scan_id": scan.previous_scan_id,
            "is_current_for_environment": scan.is_current_for_environment,
            "environment_id": scan.environment_id,
        },
        "scan": summary,
        "executive_summary": {
            "pki_assurance_level": summary.get("registry", {}).get("assurance", {}).get("assurance_level"),
            "coverage_level": summary.get("registry", {}).get("assurance", {}).get("coverage_level"),
            "pki_posture_score": summary.get("posture", {}).get("score"),
            "pki_posture_status": summary.get("posture", {}).get("status"),
            "pki_health_score": summary.get("health", {}).get("score"),
            "pki_health_status": summary.get("health", {}).get("status"),
            "best_practice_score": summary.get("best_practices", {}).get("score"),
            "best_practice_status": summary.get("best_practices", {}).get("status"),
            "posture_score_explanation": summary.get("posture", {}).get("score_explanation", []),
            "health_score_explanation": summary.get("health", {}).get("score_explanation", []),
            "best_practice_score_explanation": summary.get("best_practices", {}).get("score_explanation", []),
            "critical_findings": sum(1 for f in findings if f.severity == "Critical" and f.coverage_state == "detected"),
            "high_findings": sum(1 for f in findings if f.severity == "High" and f.coverage_state == "detected"),
            "not_assessed_summary": {
                "coverage": sum(1 for state in (scan.coverage_json or {}).values() if state in {"not_assessed", "insufficient_data"}),
                "health": summary.get("health", {}).get("counts", {}).get("Not Assessed", 0),
                "best_practices": summary.get("best_practices", {}).get("counts", {}).get("Not Assessed", 0),
            },
        },
        "posture": summary.get("posture", {}),
        "health": summary.get("health", {}),
        "best_practices": summary.get("best_practices", {}),
        "coverage": scan.coverage_json,
        "collector_coverage": summary.get("posture", {}).get("data_coverage", {}),
        "remediation_priorities": summary.get("remediation_priorities", {}),
        "top_risks": summary.get("posture", {}).get("top_risks", []),
        "evidence_summary": summary.get("registry", {}),
        "open_risks": summary.get("registry", {}).get("open_risks", []),
        "health_issues": [
            item for item in summary.get("health", {}).get("items", [])
            if item.get("status") in {"Critical", "Warning", "Not Assessed"}
        ],
        "best_practice_gaps": [
            item for item in summary.get("best_practices", {}).get("items", [])
            if item.get("status") in {"Fail", "Warning", "Not Assessed"}
        ],
        "cas": [c.name for c in db.query(CertificateAuthority).filter_by(scan_id=scan.id).all()],
        "validation_summary": validation_summary,
        "findings": [
            {
                "title": f.title,
                "severity": f.severity,
                "category": f.esc_category,
                "confidence": f.confidence,
                "coverage_state": f.coverage_state,
                "affected": f.affected_object,
                "risk_score": (f.evidence_json or {}).get("risk_score"),
                "business_impact": (f.evidence_json or {}).get("business_impact"),
                "technical_impact": (f.evidence_json or {}).get("technical_impact"),
                "score_breakdown": (f.evidence_json or {}).get("score_breakdown"),
                "remediation": f.remediation,
                "accepted_risk": getattr(f, "accepted_risk", False),
                "acceptance_id": getattr(getattr(f, "acceptance", None), "id", None),
                "structured_evidence": {
                    key: value
                    for key, value in (f.evidence_json or {}).items()
                    if key not in {"business_impact", "technical_impact", "score_breakdown"}
                },
                "validation": (
                    {
                        "validation_id": latest_validations[f.id].id,
                        "mode": latest_validations[f.id].mode,
                        "recipe_id": latest_validations[f.id].recipe_id,
                        "recipe_version": (
                            latest_validations[f.id].recipe_version
                        ),
                        "result": latest_validations[f.id].result,
                        "confidence": (
                            latest_validations[f.id].confidence
                        ),
                        "completed_at": (
                            latest_validations[f.id]
                            .completed_at.isoformat()
                            if latest_validations[f.id].completed_at
                            else None
                        ),
                        "live_commands_executed": (
                            latest_validations[f.id]
                            .safety_json.get(
                                "live_commands_executed",
                                False,
                            )
                        ),
                        "environment_changes": (
                            latest_validations[f.id]
                            .safety_json.get(
                                "environment_changes",
                                False,
                            )
                        ),
                    }
                    if f.id in latest_validations
                    else None
                ),
            }
            for f in findings
        ],
        "accepted_risks": summary.get("registry", {}).get("accepted_risks", [
            {
                "fingerprint": a.fingerprint,
                "object_name": a.object_name,
                "risk_title": a.risk_title,
                "accepted_by": a.accepted_by,
                "expiry_date": a.expiry_date,
                "business_justification": a.business_justification,
                "compensating_control": a.compensating_control,
            }
            for a in acceptances.values()
        ]),
    }
    return JSONResponse(payload)


@app.get("/reports/{scan_id}", response_class=HTMLResponse)
def report_html(scan_id: int, request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = db.query(Finding).filter_by(scan_id=scan_id).all()
    ctx = _nav_context(request, db)
    ctx.update({"scan": scan, "findings": findings})
    return templates.TemplateResponse("report.html", ctx)


@app.post("/api/v1/collector/ingest")
def collector_ingest(
    payload: CollectorPayload,
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
):
    token = authorization.replace("Bearer", "").strip()
    if token != settings.collector_api_token:
        raise HTTPException(status_code=401, detail="Invalid collector token")
    scan = IngestService.ingest(db, payload, actor="collector")
    return {"status": "ok", "scan_id": scan.id}


@app.get("/evidence-gaps", response_class=HTMLResponse)
def evidence_gaps_page(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    latest_scan = _selected_scan(request, db)
    registry = _assessment(latest_scan, "registry", {})

    gaps = []
    if isinstance(registry, dict):
        gaps = registry.get("coverage_gaps", []) or []

    def normalize(value) -> str:
        return str(value or "").strip().casefold()

    template_aliases: dict[str, str] = {}
    ca_aliases: dict[str, str] = {}

    if latest_scan:
        template_rows = (
            db.query(CertificateTemplate)
            .filter_by(scan_id=latest_scan.id)
            .all()
        )

        for template in template_rows:
            canonical_name = (
                template.display_name
                or template.name
                or "Unknown template"
            )

            for candidate in (
                template.name,
                template.display_name,
            ):
                key = normalize(candidate)
                if key:
                    template_aliases[key] = canonical_name

        ca_rows = (
            db.query(CertificateAuthority)
            .filter_by(scan_id=latest_scan.id)
            .all()
        )

        for ca in ca_rows:
            canonical_name = ca.name or ca.dns_name or "Unknown CA"

            for candidate in (
                ca.name,
                ca.dns_name,
            ):
                key = normalize(candidate)
                if key:
                    ca_aliases[key] = canonical_name

    buckets: dict[str, dict[str, list[dict]]] = {
        "templates": {},
        "cas": {},
        "other": {},
    }

    for gap in gaps:
        object_type = normalize(gap.get("object_type"))
        object_name = str(
            gap.get("object_name") or "Unknown object"
        ).strip()

        related_template = str(
            gap.get("related_template") or ""
        ).strip()

        related_ca = str(
            gap.get("related_ca") or ""
        ).strip()

        category = str(
            gap.get("category") or "Other"
        ).strip()

        object_key = normalize(object_name)
        related_template_key = normalize(related_template)
        related_ca_key = normalize(related_ca)

        # Use the actual latest-scan inventories first.
        # Do not classify "finding" or "health_check" directly,
        # because those are record types rather than asset types.
        if object_key in template_aliases:
            bucket_name = "templates"
            asset_name = template_aliases[object_key]

        elif object_key in ca_aliases:
            bucket_name = "cas"
            asset_name = ca_aliases[object_key]

        elif related_template_key in template_aliases:
            bucket_name = "templates"
            asset_name = template_aliases[related_template_key]

        elif related_ca_key in ca_aliases:
            bucket_name = "cas"
            asset_name = ca_aliases[related_ca_key]

        elif object_type in {
            "template",
            "certificate_template",
        }:
            bucket_name = "templates"
            asset_name = related_template or object_name

        elif object_type in {
            "ca",
            "certificate_authority",
        }:
            bucket_name = "cas"
            asset_name = related_ca or object_name

        else:
            bucket_name = "other"
            asset_name = (
                f"{category} — {object_name}"
                if object_name and object_name != category
                else category
            )

        buckets[bucket_name].setdefault(
            asset_name,
            [],
        ).append(gap)

    group_definitions = [
        (
            "templates",
            "Certificate Templates",
            "Template ACL, EKU, enrolment, validity, and identity-control evidence.",
        ),
        (
            "cas",
            "Certificate Authorities",
            "CA certificate, CRL, AIA, auditing, key protection, and service evidence.",
        ),
        (
            "other",
            "Other Controls",
            "Environment-wide evidence that is not linked to one CA or certificate template.",
        ),
    ]

    evidence_gap_groups = []

    for key, title, description in group_definitions:
        assets = []

        for asset_name, asset_gaps in sorted(
            buckets[key].items(),
            key=lambda item: item[0].casefold(),
        ):
            sorted_gaps = sorted(
                asset_gaps,
                key=lambda gap: (
                    str(gap.get("category") or ""),
                    str(gap.get("title") or ""),
                ),
            )

            assets.append(
                {
                    "name": asset_name,
                    "gap_count": len(sorted_gaps),
                    "gaps": sorted_gaps,
                }
            )

        if assets:
            evidence_gap_groups.append(
                {
                    "key": key,
                    "title": title,
                    "description": description,
                    "asset_count": len(assets),
                    "gap_count": sum(
                        asset["gap_count"]
                        for asset in assets
                    ),
                    "assets": assets,
                }
            )

    ctx = _nav_context(request, db)
    ctx.update(
        {
            "scan": latest_scan,
            "evidence_gap_count": len(gaps),
            "evidence_gap_groups": evidence_gap_groups,
            "template_gap_assets": len(
                buckets["templates"]
            ),
            "ca_gap_assets": len(
                buckets["cas"]
            ),
            "other_gap_assets": len(
                buckets["other"]
            ),
        }
    )

    return templates.TemplateResponse(
        "evidence_gaps.html",
        ctx,
    )
