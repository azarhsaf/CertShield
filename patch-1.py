#!/usr/bin/env python3
from datetime import datetime
from pathlib import Path
from shutil import copy2

ROOT = Path('/opt/certshield')
MON = ROOT / 'app/services/monitoring_agent.py'
ING = ROOT / 'app/services/ingest.py'
MAIN = ROOT / 'app/main.py'
STAMP = datetime.now().strftime('%Y%m%d-%H%M%S')

for path in (MON, ING, MAIN):
    if not path.exists():
        raise SystemExit(f'Missing file: {path}')
    backup = path.with_name(path.name + f'.bak.auto-env-{STAMP}')
    copy2(path, backup)
    print(f'Backup created: {backup}')


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected 1 match, found {count}')
    return text.replace(old, new, 1)

# ------------------------------------------------------------------
# Monitoring service: resolve/create environment from agent identity.
# ------------------------------------------------------------------
text = MON.read_text()
marker = '\ndef save_heartbeat(\n'
if marker not in text:
    raise SystemExit('save_heartbeat marker not found')

helper = r'''

def _normalise_identity(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")


def resolve_monitoring_environment(
    db: Session,
    *,
    environment_id: int | None,
    environment_name: str,
    domain_name: str,
    forest_name: str,
    collector_type: str,
    hostname: str,
) -> tuple[int, bool]:
    """Resolve an existing environment or create a monitoring-only one."""

    env_name = _normalise_identity(environment_name)
    domain = _normalise_identity(domain_name)
    forest = _normalise_identity(forest_name)
    kind = _normalise_identity(collector_type) or "adcs"
    identity_supplied = bool(env_name or domain or forest)

    def first(sql: str, params: dict):
        return db.execute(text(sql), params).mappings().first()

    matched = None

    if domain:
        matched = first(
            """
            SELECT * FROM pki_environments
            WHERE is_active = 1
              AND lower(coalesce(collector_type, '')) = :kind
              AND lower(trim(coalesce(domain_name, ''))) = :domain
            ORDER BY CASE WHEN last_scan_id IS NOT NULL THEN 0 ELSE 1 END, id
            LIMIT 1
            """,
            {"kind": kind, "domain": domain},
        )

    if not matched and forest:
        matched = first(
            """
            SELECT * FROM pki_environments
            WHERE is_active = 1
              AND lower(coalesce(collector_type, '')) = :kind
              AND lower(trim(coalesce(forest_name, ''))) = :forest
            ORDER BY CASE WHEN last_scan_id IS NOT NULL THEN 0 ELSE 1 END, id
            LIMIT 1
            """,
            {"kind": kind, "forest": forest},
        )

    if not matched and env_name:
        matched = first(
            """
            SELECT * FROM pki_environments
            WHERE is_active = 1
              AND lower(coalesce(collector_type, '')) = :kind
              AND lower(trim(coalesce(name, ''))) = :name
            ORDER BY CASE WHEN last_scan_id IS NOT NULL THEN 0 ELSE 1 END, id
            LIMIT 1
            """,
            {"kind": kind, "name": env_name},
        )

    if matched:
        db.execute(
            text(
                """
                UPDATE pki_environments
                SET domain_name = CASE WHEN :domain_name <> '' THEN :domain_name ELSE domain_name END,
                    forest_name = CASE WHEN :forest_name <> '' THEN :forest_name ELSE forest_name END,
                    updated_at = :updated_at
                WHERE id = :id
                """
            ),
            {
                "id": int(matched["id"]),
                "domain_name": domain_name.strip(),
                "forest_name": forest_name.strip(),
                "updated_at": _now_text(),
            },
        )
        db.commit()
        return int(matched["id"]), False

    # Backward compatibility for old agents. New agents must send identity.
    if environment_id and not identity_supplied:
        legacy = first(
            "SELECT id FROM pki_environments WHERE id = :id AND is_active = 1",
            {"id": int(environment_id)},
        )
        if legacy:
            return int(legacy["id"]), False

    if not identity_supplied:
        raise HTTPException(
            status_code=400,
            detail=(
                "Monitoring heartbeat must include environment_name, "
                "domain_name or forest_name"
            ),
        )

    identity = domain or forest or env_name or _normalise_identity(hostname) or "unknown"
    safe_identity = "".join(
        char if char.isalnum() or char in ".-_" else "-"
        for char in identity
    )
    environment_key = f"monitoring:{kind}:{safe_identity}"

    existing_key = first(
        "SELECT id FROM pki_environments WHERE environment_key = :key LIMIT 1",
        {"key": environment_key},
    )
    if existing_key:
        return int(existing_key["id"]), False

    display_name = (
        environment_name.strip()
        or domain_name.strip()
        or forest_name.strip()
        or hostname.strip()
        or "Monitoring environment"
    )
    now = _now_text()

    db.execute(
        text(
            """
            INSERT INTO pki_environments (
                name, environment_key, collector_type, domain_name,
                forest_name, pki_label, description, is_demo,
                is_active, created_at, updated_at
            ) VALUES (
                :name, :key, :kind, :domain_name,
                :forest_name, :pki_label, :description, 0,
                1, :created_at, :updated_at
            )
            """
        ),
        {
            "name": display_name,
            "key": environment_key,
            "kind": kind,
            "domain_name": domain_name.strip(),
            "forest_name": forest_name.strip(),
            "pki_label": display_name,
            "description": (
                "Created automatically from a monitoring-agent heartbeat. "
                "Collector data is pending."
            ),
            "created_at": now,
            "updated_at": now,
        },
    )
    new_id = int(db.execute(text("SELECT last_insert_rowid()" )).scalar_one())
    db.commit()
    return new_id, True
'''

text = text.replace(marker, helper + marker, 1)

old = '''def save_heartbeat(
    db: Session,
    *,
    environment_id: int,
    agent_key: str,
    hostname: str,
    ca_name: str,
    agent_version: str,
    state: dict,
    source_ip: str,
) -> dict:
    environment = db.execute(
        text("SELECT id FROM pki_environments " "WHERE id = :id AND is_active = 1"),
        {"id": environment_id},
    ).scalar()

    if not environment:
        raise HTTPException(
            status_code=404,
            detail="PKI environment not found",
        )
'''
new = '''def save_heartbeat(
    db: Session,
    *,
    environment_id: int | None,
    environment_name: str,
    domain_name: str,
    forest_name: str,
    collector_type: str,
    agent_key: str,
    hostname: str,
    ca_name: str,
    agent_version: str,
    state: dict,
    source_ip: str,
) -> dict:
    environment_id, environment_created = resolve_monitoring_environment(
        db,
        environment_id=environment_id,
        environment_name=environment_name,
        domain_name=domain_name,
        forest_name=forest_name,
        collector_type=collector_type,
        hostname=hostname,
    )
'''
text = replace_once(text, old, new, 'save_heartbeat header')

text = replace_once(
    text,
    '            text("SELECT * FROM monitoring_agents " "WHERE agent_key = :agent_key AND is_active = 1"),\n',
    '            text("SELECT * FROM monitoring_agents " "WHERE agent_key = :agent_key"),\n',
    '_agent_row lookup',
)

old = '''    if existing:
        if int(existing["environment_id"]) != int(environment_id):
            raise HTTPException(
                status_code=409,
                detail=("Agent key belongs to another environment"),
            )

        assignments = []
'''
new = '''    if existing:
        assignments = []
'''
text = replace_once(text, old, new, 'agent migration conflict')

old = '    return _agent_row(db, agent_key)\n'
new = '''    saved = _agent_row(db, agent_key)
    if saved is None:
        raise HTTPException(
            status_code=500,
            detail="Monitoring agent heartbeat was not persisted",
        )
    result = dict(saved)
    result["environment_created"] = environment_created
    return result
'''
text = replace_once(text, old, new, 'save_heartbeat return')
MON.write_text(text)

# ------------------------------------------------------------------
# Collector ingestion: reuse a monitoring-only environment by domain.
# ------------------------------------------------------------------
text = ING.read_text()
text = replace_once(
    text,
    'from sqlalchemy.orm import Session\n',
    'from sqlalchemy import func\nfrom sqlalchemy.orm import Session\n',
    'ingest import',
)
start = text.index('def _resolve_environment(')
end = text.index('\n\nclass IngestService:', start)
resolver = r'''def _resolve_environment(db: Session, payload: CollectorPayload) -> PkiEnvironment:
    key = _environment_key(payload)
    kind = (payload.collector_type or "generic").strip().lower()

    env = db.query(PkiEnvironment).filter_by(environment_key=key).first()

    if not env and payload.domain_name.strip():
        env = (
            db.query(PkiEnvironment)
            .filter(
                PkiEnvironment.is_active.is_(True),
                func.lower(PkiEnvironment.collector_type) == kind,
                func.lower(func.trim(PkiEnvironment.domain_name))
                == payload.domain_name.strip().lower(),
            )
            .order_by(PkiEnvironment.last_scan_id.is_(None), PkiEnvironment.id)
            .first()
        )

    if not env and payload.forest_name.strip():
        env = (
            db.query(PkiEnvironment)
            .filter(
                PkiEnvironment.is_active.is_(True),
                func.lower(PkiEnvironment.collector_type) == kind,
                func.lower(func.trim(PkiEnvironment.forest_name))
                == payload.forest_name.strip().lower(),
            )
            .order_by(PkiEnvironment.last_scan_id.is_(None), PkiEnvironment.id)
            .first()
        )

    now = datetime.utcnow()

    if env:
        env.updated_at = now
        env.collector_type = payload.collector_type or env.collector_type
        if payload.domain_name:
            env.domain_name = payload.domain_name
        if payload.forest_name:
            env.forest_name = payload.forest_name
        if payload.pki_label:
            env.pki_label = payload.pki_label
        if env.description.startswith(
            "Created automatically from a monitoring-agent"
        ):
            env.description = "Monitoring and collector data are available."
        return env

    name = (
        payload.environment_name.strip()
        or payload.pki_label.strip()
        or payload.domain_name
        or key
    )
    if _is_demo_payload(payload) and not name.lower().startswith("demo"):
        name = f"Demo - {name}"

    env = PkiEnvironment(
        name=name,
        environment_key=key,
        collector_type=payload.collector_type or "generic",
        domain_name=payload.domain_name or "",
        forest_name=payload.forest_name or "",
        pki_label=payload.pki_label or name,
        is_demo=_is_demo_payload(payload),
        is_active=True,
        created_at=now,
        updated_at=now,
    )
    db.add(env)
    db.flush()
    return env
'''
text = text[:start] + resolver + text[end:]
ING.write_text(text)

# ------------------------------------------------------------------
# Heartbeat API: identity is authoritative; numeric ID is optional.
# ------------------------------------------------------------------
text = MAIN.read_text()
text = replace_once(
    text,
    '''    required = (
        "environment_id",
        "agent_key",
        "hostname",
    )
''',
    '''    required = (
        "agent_key",
        "hostname",
    )
''',
    'heartbeat required fields',
)

old = '''    agent = save_heartbeat(
        db,
        environment_id=int(payload["environment_id"]),
        agent_key=str(payload["agent_key"]),
        hostname=str(payload["hostname"]),
        ca_name=str(payload.get("ca_name") or ""),
        agent_version=str(payload.get("agent_version") or ""),
        state=payload.get("state") or {},
        source_ip=(request.client.host if request.client else ""),
    )
'''
new = '''    supplied_environment_id = payload.get("environment_id")

    agent = save_heartbeat(
        db,
        environment_id=(
            int(supplied_environment_id)
            if supplied_environment_id not in (None, "")
            else None
        ),
        environment_name=str(payload.get("environment_name") or ""),
        domain_name=str(payload.get("domain_name") or ""),
        forest_name=str(payload.get("forest_name") or ""),
        collector_type=str(payload.get("collector_type") or "adcs"),
        agent_key=str(payload["agent_key"]),
        hostname=str(payload["hostname"]),
        ca_name=str(payload.get("ca_name") or ""),
        agent_version=str(payload.get("agent_version") or ""),
        state=payload.get("state") or {},
        source_ip=(request.client.host if request.client else ""),
    )
'''
text = replace_once(text, old, new, 'heartbeat save call')

old = '''    return {
        "status": "ok",
        "agent_id": agent["id"],
        "server_time": datetime.utcnow().isoformat(),
    }
'''
new = '''    return {
        "status": "ok",
        "agent_id": agent["id"],
        "environment_id": agent["environment_id"],
        "environment_created": bool(agent.get("environment_created")),
        "server_time": datetime.utcnow().isoformat(),
    }
'''
text = replace_once(text, old, new, 'heartbeat response')
MAIN.write_text(text)

print('Phase 1 auto-environment patch applied.')
print('Do not restart until Ruff and tests pass.')

