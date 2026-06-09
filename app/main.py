from collections import Counter
from contextlib import contextmanager

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
    IssuedCertificate,
    RiskAcceptance,
    Scan,
    User,
)
from app.schemas.collector import CollectorPayload
from app.services.assessment_registry import build_assessment_registry
from app.services.ingest import IngestService
from app.services.pki_hierarchy import build_pki_hierarchy
from app.services.posture_assessment import assess_pki_posture
from app.services.risk_acceptance import (
    accepted_counts,
    active_acceptance_map,
    decorate_findings,
    finding_fingerprint,
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


def _nav_context(request: Request) -> dict:
    return {
        "request": request,
        "current_user": request.session.get("user"),
        "app_version": settings.app_version,
        "build_name": settings.build_name,
        "build_label": settings.build_label,
    }


def _assessment(scan: Scan | None, key: str, default):
    if not scan:
        return default
    return (scan.summary_json or {}).get(key, default)



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
    registry = build_assessment_registry(
        cas, templates_data, certificates, findings, summary.get("health", {}), summary.get("best_practices", {}), acceptances
    )
    posture = assess_pki_posture(
        findings,
        summary.get("health", {}),
        summary.get("best_practices", {}),
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
    return db.query(Scan).order_by(Scan.id.desc()).first()


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
    latest_scan = _latest_scan(db)
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
    ctx = _nav_context(request)
    posture = _assessment(latest_scan, "posture", {})
    registry = _assessment(latest_scan, "registry", {})
    assurance = registry.get("assurance", posture.get("assurance", {})) if isinstance(registry, dict) else {}
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
    latest_scan = _latest_scan(db)
    records = query.filter_by(scan_id=latest_scan.id).all() if latest_scan else []
    ctx = _nav_context(request)
    ctx.update({key: records, "scan": latest_scan})
    return templates.TemplateResponse(name, ctx)


@app.get("/pki-hierarchy", response_class=HTMLResponse)
def pki_hierarchy_page(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    latest_scan = _latest_scan(db)
    cas = db.query(CertificateAuthority).filter_by(scan_id=latest_scan.id).all() if latest_scan else []
    health = _assessment(latest_scan, "health", {})
    best_practices = _assessment(latest_scan, "best_practices", {})
    ctx = _nav_context(request)
    ctx.update({"scan": latest_scan, "hierarchy": build_pki_hierarchy(cas, health, best_practices)})
    return templates.TemplateResponse("pki_hierarchy.html", ctx)


@app.get("/pki-posture", response_class=HTMLResponse)
def pki_posture_page(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    latest_scan = _latest_scan(db)
    registry = _assessment(latest_scan, "registry", {})
    ctx = _nav_context(request)
    ctx.update({
        "scan": latest_scan,
        "posture": _assessment(latest_scan, "posture", {}),
        "registry": registry,
        "assurance": registry.get("assurance", {}) if isinstance(registry, dict) else {},
    })
    return templates.TemplateResponse("pki_posture.html", ctx)


@app.get("/pki-health", response_class=HTMLResponse)
def pki_health_page(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    latest_scan = _latest_scan(db)
    ctx = _nav_context(request)
    ctx.update({"scan": latest_scan, "health": _assessment(latest_scan, "health", {}), "registry": _assessment(latest_scan, "registry", {})})
    return templates.TemplateResponse("pki_health.html", ctx)


@app.get("/best-practices", response_class=HTMLResponse)
def best_practices_page(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    latest_scan = _latest_scan(db)
    accepted = 0
    if latest_scan:
        scan_findings = db.query(Finding).filter_by(scan_id=latest_scan.id).all()
        accepted = accepted_counts(scan_findings, active_acceptance_map(db))["accepted_total"]
    ctx = _nav_context(request)
    ctx.update({
        "scan": latest_scan,
        "best_practices": _assessment(latest_scan, "best_practices", {}),
        "registry": _assessment(latest_scan, "registry", {}),
        "accepted_risk_count": accepted,
    })
    return templates.TemplateResponse("best_practices.html", ctx)


@app.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    scans = db.query(Scan).order_by(Scan.id.desc()).all()
    ctx = _nav_context(request)
    ctx.update({"scans": scans})
    return templates.TemplateResponse("reports.html", ctx)


@app.get("/cas", response_class=HTMLResponse)
def cas_page(request: Request, db: Session = Depends(get_db)):
    return render_page(request, "cas.html", db.query(CertificateAuthority), "cas", db)


@app.get("/templates", response_class=HTMLResponse)
def template_page(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    latest_scan = _latest_scan(db)
    records = (
        db.query(CertificateTemplate)
        .options(joinedload(CertificateTemplate.permissions))
        .filter_by(scan_id=latest_scan.id)
        .all()
        if latest_scan
        else []
    )
    template_risks = {}
    if latest_scan:
        findings = db.query(Finding).filter_by(scan_id=latest_scan.id).all()
        acceptances = active_acceptance_map(db)
        for finding in findings:
            accepted = finding_fingerprint(finding) in acceptances
            risk = template_risks.setdefault(
                finding.affected_object,
                {"open": 0, "accepted": 0, "critical": 0, "high": 0, "issues": []},
            )
            if accepted:
                risk["accepted"] += 1
            else:
                risk["open"] += 1
                if finding.severity == "Critical":
                    risk["critical"] += 1
                elif finding.severity == "High":
                    risk["high"] += 1
            risk["issues"].append({"title": finding.title, "severity": finding.severity, "accepted": accepted})
    ctx = _nav_context(request)
    ctx.update({"templates_data": records, "scan": latest_scan, "template_risks": template_risks})
    return templates.TemplateResponse("templates.html", ctx)


@app.get("/findings", response_class=HTMLResponse)
def findings_page(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    latest_scan = _latest_scan(db)
    records = (
        db.query(Finding)
        .filter_by(scan_id=latest_scan.id)
        .order_by(func.instr("Critical,High,Medium,Low", Finding.severity), Finding.id.desc())
        .all()
        if latest_scan
        else []
    )
    records = decorate_findings(records, active_acceptance_map(db))
    ctx = _nav_context(request)
    ctx.update({"findings": records, "scan": latest_scan, "csrf_token": issue_csrf_token(request)})
    return templates.TemplateResponse("findings.html", ctx)


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
    return RedirectResponse("/findings", status_code=303)


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


@app.get("/findings/{finding_id}/simulate", response_class=HTMLResponse)
def finding_simulation_page(finding_id: int, request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    finding = db.query(Finding).filter_by(id=finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    ctx = _nav_context(request)
    ctx.update({"finding": finding, "simulation": finding.simulation_json or {}})
    return templates.TemplateResponse("simulation.html", ctx)


@app.get("/certificates", response_class=HTMLResponse)
def certs_page(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    latest_scan = _latest_scan(db)
    records = db.query(IssuedCertificate).filter_by(scan_id=latest_scan.id).all() if latest_scan else []
    ctx = _nav_context(request)
    ctx.update({"certificates": records, "scan": latest_scan})
    return templates.TemplateResponse("certificates.html", ctx)


@app.get("/history", response_class=HTMLResponse)
def history_page(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    scans = db.query(Scan).order_by(Scan.id.desc()).all()
    ctx = _nav_context(request)
    ctx["scans"] = scans
    return templates.TemplateResponse("history.html", ctx)


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    latest_scan = _latest_scan(db)
    masked = settings.collector_api_token[:4] + "..." + settings.collector_api_token[-4:]
    ctx = _nav_context(request)
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


@app.get("/reports/{scan_id}.json")
def export_json(scan_id: int, request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
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
    payload = {
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
    ctx = _nav_context(request)
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
