from collections import Counter
from contextlib import contextmanager

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload
from starlette.middleware.sessions import SessionMiddleware

from app.core.config import get_settings
from app.core.security import (
    ensure_authenticated,
    hash_password,
    issue_csrf_token,
    validate_csrf,
    verify_password,
)
from app.db.session import Base, SessionLocal, engine, get_db
from app.models.entities import (
    AuditLog,
    CertificateAuthority,
    CertificateTemplate,
    Finding,
    IssuedCertificate,
    Scan,
    User,
)
from app.schemas.collector import CollectorPayload
from app.services.ingest import IngestService

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


def _nav_context(request: Request) -> dict:
    return {"request": request, "current_user": request.session.get("user")}


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
    return {"status": "ok", "app": settings.app_name, "environment": settings.app_env}


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
    latest_scan = db.query(Scan).order_by(Scan.id.desc()).first()
    severity = {sev: 0 for sev in SEVERITY_ORDER}
    recent_certs: list[IssuedCertificate] = []
    if latest_scan:
        severity = _severity_counts(db, latest_scan.id)
        recent_certs = (
            db.query(IssuedCertificate)
            .filter_by(scan_id=latest_scan.id)
            .order_by(IssuedCertificate.id.desc())
            .limit(10)
            .all()
        )
    ctx = _nav_context(request)
    ctx.update(
        {
            "scan": latest_scan,
            "severity": severity,
            "severity_order": SEVERITY_ORDER,
            "recent_certs": recent_certs,
        }
    )
    return templates.TemplateResponse("dashboard.html", ctx)


def render_page(request: Request, name: str, query, key: str, db: Session):
    ensure_authenticated(request)
    latest_scan = db.query(Scan).order_by(Scan.id.desc()).first()
    records = query.filter_by(scan_id=latest_scan.id).all() if latest_scan else []
    ctx = _nav_context(request)
    ctx.update({key: records, "scan": latest_scan})
    return templates.TemplateResponse(name, ctx)


@app.get("/cas", response_class=HTMLResponse)
def cas_page(request: Request, db: Session = Depends(get_db)):
    return render_page(request, "cas.html", db.query(CertificateAuthority), "cas", db)


@app.get("/templates", response_class=HTMLResponse)
def template_page(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    latest_scan = db.query(Scan).order_by(Scan.id.desc()).first()
    records = (
        db.query(CertificateTemplate)
        .options(joinedload(CertificateTemplate.permissions))
        .filter_by(scan_id=latest_scan.id)
        .all()
        if latest_scan
        else []
    )
    ctx = _nav_context(request)
    ctx.update({"templates_data": records, "scan": latest_scan})
    return templates.TemplateResponse("templates.html", ctx)


@app.get("/findings", response_class=HTMLResponse)
def findings_page(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    latest_scan = db.query(Scan).order_by(Scan.id.desc()).first()
    records = (
        db.query(Finding)
        .filter_by(scan_id=latest_scan.id)
        .order_by(
            func.instr("Critical,High,Medium,Low", Finding.severity),
            Finding.id.desc(),
        )
        .all()
        if latest_scan
        else []
    )
    ctx = _nav_context(request)
    ctx.update({"findings": records, "scan": latest_scan})
    return templates.TemplateResponse("findings.html", ctx)


@app.get("/certificates", response_class=HTMLResponse)
def certs_page(request: Request, db: Session = Depends(get_db)):
    return render_page(request, "certificates.html", db.query(IssuedCertificate), "certificates", db)


@app.get("/history", response_class=HTMLResponse)
def history_page(request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    scans = db.query(Scan).order_by(Scan.id.desc()).all()
    ctx = _nav_context(request)
    ctx["scans"] = scans
    return templates.TemplateResponse("history.html", ctx)


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    ensure_authenticated(request)
    masked = settings.collector_api_token[:4] + "..." + settings.collector_api_token[-4:]
    ctx = _nav_context(request)
    ctx.update(
        {
            "collector_token": masked,
            "collector_endpoint": "/api/v1/collector/ingest",
            "bind_host": settings.bind_host,
            "bind_port": settings.bind_port,
        }
    )
    return templates.TemplateResponse("settings.html", ctx)


@app.get("/reports/{scan_id}.json")
def export_json(scan_id: int, request: Request, db: Session = Depends(get_db)):
    ensure_authenticated(request)
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    payload = {
        "scan": scan.summary_json,
        "cas": [c.name for c in db.query(CertificateAuthority).filter_by(scan_id=scan.id).all()],
        "findings": [
            {"title": f.title, "severity": f.severity, "affected": f.affected_object}
            for f in db.query(Finding).filter_by(scan_id=scan.id).all()
        ],
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
