from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

CONNECTED_SECONDS = 45
ALLOWED_COMMANDS = {"enable_ca_auditing"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_text() -> str:
    return _now().isoformat()


def _load(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def ensure_monitoring_agent_schema(
    db: Session,
) -> None:
    """Create or upgrade monitoring-agent tables safely."""

    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS monitoring_agents (
                id INTEGER PRIMARY KEY,
                environment_id INTEGER NOT NULL,
                agent_key VARCHAR(255) NOT NULL UNIQUE,
                hostname VARCHAR(255) NOT NULL,
                ca_name VARCHAR(255) DEFAULT '',
                agent_version VARCHAR(50) DEFAULT '',
                status VARCHAR(30) DEFAULT 'registered',
                state_json JSON DEFAULT '{}',
                last_heartbeat DATETIME,
                last_ip VARCHAR(100) DEFAULT '',
                created_at DATETIME,
                updated_at DATETIME,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY(environment_id)
                    REFERENCES pki_environments(id)
            )
            """
        )
    )

    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS monitoring_commands (
                id INTEGER PRIMARY KEY,
                environment_id INTEGER NOT NULL,
                agent_id INTEGER NOT NULL,
                command_type VARCHAR(80) NOT NULL,
                status VARCHAR(30) DEFAULT 'queued',
                requested_by VARCHAR(100) NOT NULL,
                requested_at DATETIME,
                picked_up_at DATETIME,
                completed_at DATETIME,
                result_json JSON DEFAULT '{}',
                FOREIGN KEY(environment_id)
                    REFERENCES pki_environments(id),
                FOREIGN KEY(agent_id)
                    REFERENCES monitoring_agents(id)
            )
            """
        )
    )

    agent_columns = {row[1] for row in db.execute(text("PRAGMA table_info(monitoring_agents)")).fetchall()}

    agent_alters = {
        "environment_id": ("ALTER TABLE monitoring_agents " "ADD COLUMN environment_id INTEGER"),
        "agent_key": ("ALTER TABLE monitoring_agents " "ADD COLUMN agent_key VARCHAR(255) DEFAULT ''"),
        "hostname": ("ALTER TABLE monitoring_agents " "ADD COLUMN hostname VARCHAR(255) DEFAULT ''"),
        "ca_name": ("ALTER TABLE monitoring_agents " "ADD COLUMN ca_name VARCHAR(255) DEFAULT ''"),
        "agent_version": ("ALTER TABLE monitoring_agents " "ADD COLUMN agent_version VARCHAR(50) DEFAULT ''"),
        "status": ("ALTER TABLE monitoring_agents " "ADD COLUMN status VARCHAR(30) " "DEFAULT 'registered'"),
        "state_json": ("ALTER TABLE monitoring_agents " "ADD COLUMN state_json JSON DEFAULT '{}'"),
        "last_heartbeat": ("ALTER TABLE monitoring_agents " "ADD COLUMN last_heartbeat DATETIME"),
        "last_ip": ("ALTER TABLE monitoring_agents " "ADD COLUMN last_ip VARCHAR(100) DEFAULT ''"),
        "created_at": ("ALTER TABLE monitoring_agents " "ADD COLUMN created_at DATETIME"),
        "updated_at": ("ALTER TABLE monitoring_agents " "ADD COLUMN updated_at DATETIME"),
        "is_active": ("ALTER TABLE monitoring_agents " "ADD COLUMN is_active BOOLEAN DEFAULT 1"),
    }

    for column, statement in agent_alters.items():
        if column not in agent_columns:
            db.execute(text(statement))

    command_columns = {row[1] for row in db.execute(text("PRAGMA table_info(monitoring_commands)")).fetchall()}

    command_alters = {
        "environment_id": ("ALTER TABLE monitoring_commands " "ADD COLUMN environment_id INTEGER"),
        "agent_id": ("ALTER TABLE monitoring_commands " "ADD COLUMN agent_id INTEGER"),
        "command_type": ("ALTER TABLE monitoring_commands " "ADD COLUMN command_type VARCHAR(80) DEFAULT ''"),
        "status": ("ALTER TABLE monitoring_commands " "ADD COLUMN status VARCHAR(30) DEFAULT 'queued'"),
        "requested_by": ("ALTER TABLE monitoring_commands " "ADD COLUMN requested_by VARCHAR(100) DEFAULT 'unknown'"),
        "requested_at": ("ALTER TABLE monitoring_commands " "ADD COLUMN requested_at DATETIME"),
        "picked_up_at": ("ALTER TABLE monitoring_commands " "ADD COLUMN picked_up_at DATETIME"),
        "completed_at": ("ALTER TABLE monitoring_commands " "ADD COLUMN completed_at DATETIME"),
        "result_json": ("ALTER TABLE monitoring_commands " "ADD COLUMN result_json JSON DEFAULT '{}'"),
    }

    for column, statement in command_alters.items():
        if column not in command_columns:
            db.execute(text(statement))

    refreshed_agent_columns = {row[1] for row in db.execute(text("PRAGMA table_info(monitoring_agents)")).fetchall()}

    if "last_seen_at" in refreshed_agent_columns and "last_heartbeat" in refreshed_agent_columns:
        db.execute(text("UPDATE monitoring_agents " "SET last_heartbeat = last_seen_at " "WHERE last_heartbeat IS NULL"))

    indexes = (
        "CREATE INDEX IF NOT EXISTS " "ix_monitoring_agents_environment " "ON monitoring_agents(environment_id)",
        "CREATE INDEX IF NOT EXISTS " "ix_monitoring_agents_heartbeat " "ON monitoring_agents(last_heartbeat)",
        "CREATE INDEX IF NOT EXISTS " "ix_monitoring_commands_agent_status " "ON monitoring_commands(agent_id, status)",
    )

    for statement in indexes:
        db.execute(text(statement))

    db.commit()


def authorize_monitoring_agent(
    authorization: str | None,
    expected_token: str,
) -> None:
    supplied = ""
    if authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    if not expected_token or supplied != expected_token:
        raise HTTPException(
            status_code=401,
            detail="Invalid monitoring agent token",
        )


def _agent_row(db: Session, agent_key: str):
    return (
        db.execute(
            text("SELECT * FROM monitoring_agents " "WHERE agent_key = :agent_key AND is_active = 1"),
            {"agent_key": agent_key},
        )
        .mappings()
        .first()
    )


def _normalize_environment_identity(
    value: Any,
) -> str:
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
) -> int:
    normalized_type = _normalize_environment_identity(collector_type) or "adcs"

    normalized_domain = _normalize_environment_identity(domain_name)

    normalized_forest = _normalize_environment_identity(forest_name)

    normalized_name = _normalize_environment_identity(environment_name)

    identity_supplied = bool(normalized_domain or normalized_forest or normalized_name)

    def find_one(
        sql: str,
        parameters: dict,
    ):
        return (
            db.execute(
                text(sql),
                parameters,
            )
            .mappings()
            .first()
        )

    matched = None

    if normalized_domain:
        matched = find_one(
            """
            SELECT id
            FROM pki_environments
            WHERE is_active = 1
              AND lower(
                    coalesce(
                        collector_type,
                        ''
                    )
                  ) = :collector_type
              AND lower(
                    trim(
                        coalesce(
                            domain_name,
                            ''
                        )
                    )
                  ) = :domain_name
            ORDER BY
                CASE
                    WHEN last_scan_id IS NOT NULL
                    THEN 0
                    ELSE 1
                END,
                id
            LIMIT 1
            """,
            {
                "collector_type": normalized_type,
                "domain_name": normalized_domain,
            },
        )

    if not matched and normalized_forest:
        matched = find_one(
            """
            SELECT id
            FROM pki_environments
            WHERE is_active = 1
              AND lower(
                    coalesce(
                        collector_type,
                        ''
                    )
                  ) = :collector_type
              AND lower(
                    trim(
                        coalesce(
                            forest_name,
                            ''
                        )
                    )
                  ) = :forest_name
            ORDER BY
                CASE
                    WHEN last_scan_id IS NOT NULL
                    THEN 0
                    ELSE 1
                END,
                id
            LIMIT 1
            """,
            {
                "collector_type": normalized_type,
                "forest_name": normalized_forest,
            },
        )

    if not matched and normalized_name:
        matched = find_one(
            """
            SELECT id
            FROM pki_environments
            WHERE is_active = 1
              AND lower(
                    coalesce(
                        collector_type,
                        ''
                    )
                  ) = :collector_type
              AND lower(
                    trim(
                        coalesce(
                            name,
                            ''
                        )
                    )
                  ) = :environment_name
            ORDER BY
                CASE
                    WHEN last_scan_id IS NOT NULL
                    THEN 0
                    ELSE 1
                END,
                id
            LIMIT 1
            """,
            {
                "collector_type": normalized_type,
                "environment_name": normalized_name,
            },
        )

    if matched:
        return int(matched["id"])

    # Temporary backward compatibility for
    # already-installed agents.
    if environment_id and not identity_supplied:
        legacy = find_one(
            """
            SELECT id
            FROM pki_environments
            WHERE id = :environment_id
              AND is_active = 1
            """,
            {"environment_id": int(environment_id)},
        )

        if legacy:
            return int(legacy["id"])

    if not identity_supplied:
        raise HTTPException(
            status_code=400,
            detail=("Monitoring heartbeat must include " "environment_name, domain_name " "or forest_name"),
        )

    identity = normalized_domain or normalized_forest or normalized_name or _normalize_environment_identity(hostname) or "unknown"

    safe_identity = "".join(character if (character.isalnum() or character in ".-_") else "-" for character in identity)

    environment_key = f"monitoring:" f"{normalized_type}:" f"{safe_identity}"

    existing = find_one(
        """
        SELECT id
        FROM pki_environments
        WHERE environment_key = :environment_key
        LIMIT 1
        """,
        {"environment_key": environment_key},
    )

    if existing:
        return int(existing["id"])

    display_name = environment_name.strip() or domain_name.strip() or forest_name.strip() or hostname.strip() or "Monitoring environment"

    now = _now_text()

    db.execute(
        text(
            """
            INSERT INTO pki_environments (
                name,
                environment_key,
                collector_type,
                domain_name,
                forest_name,
                pki_label,
                description,
                is_demo,
                is_active,
                created_at,
                updated_at
            )
            VALUES (
                :name,
                :environment_key,
                :collector_type,
                :domain_name,
                :forest_name,
                :pki_label,
                :description,
                0,
                1,
                :created_at,
                :updated_at
            )
            """
        ),
        {
            "name": display_name,
            "environment_key": environment_key,
            "collector_type": normalized_type,
            "domain_name": domain_name.strip(),
            "forest_name": forest_name.strip(),
            "pki_label": display_name,
            "description": ("Created automatically from a " "monitoring-agent heartbeat. " "Collector data is pending."),
            "created_at": now,
            "updated_at": now,
        },
    )

    created_id = db.execute(text("SELECT last_insert_rowid()")).scalar_one()

    db.commit()

    return int(created_id)


def save_heartbeat(
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
    environment_id = resolve_monitoring_environment(
        db,
        environment_id=environment_id,
        environment_name=environment_name,
        domain_name=domain_name,
        forest_name=forest_name,
        collector_type=collector_type,
        hostname=hostname,
    )

    existing = _agent_row(db, agent_key)
    now = _now_text()
    state_json = json.dumps(state or {})

    auditing = (state or {}).get("auditing") or {}

    policy_enabled = bool(auditing.get("policy_enabled"))

    audit_filter = int(auditing.get("audit_filter") or 0)

    security_log_access = bool(auditing.get("security_log_access"))

    audit_ready = bool(policy_enabled and audit_filter == 127 and security_log_access)

    capabilities_json = json.dumps(
        {
            "security_log_access": security_log_access,
            "services": ((state or {}).get("services") or {}),
            "resources": ((state or {}).get("resources") or {}),
        }
    )

    table_info = db.execute(text("PRAGMA table_info(monitoring_agents)")).fetchall()

    schema = {
        row[1]: {
            "type": str(row[2] or ""),
            "not_null": bool(row[3]),
            "default": row[4],
            "primary_key": bool(row[5]),
        }
        for row in table_info
    }

    values = {
        "environment_id": environment_id,
        "agent_key": agent_key,
        "hostname": hostname,
        "ca_name": ca_name,
        "agent_version": agent_version,
        "status": "online",
        "state_json": state_json,
        "last_heartbeat": now,
        "last_ip": source_ip,
        "created_at": now,
        "updated_at": now,
        "is_active": 1,
        "legacy_version": agent_version,
        "legacy_last_seen_at": now,
        "legacy_payload_json": state_json,
        "legacy_name": hostname,
        "legacy_audit_success_enabled": int(policy_enabled),
        "legacy_audit_failure_enabled": int(policy_enabled),
        "legacy_audit_filter": audit_filter,
        "legacy_audit_ready": int(audit_ready),
        "legacy_capabilities_json": capabilities_json,
        "legacy_metadata_json": state_json,
    }

    canonical_fields = (
        ("environment_id", "environment_id"),
        ("agent_key", "agent_key"),
        ("hostname", "hostname"),
        ("ca_name", "ca_name"),
        ("agent_version", "agent_version"),
        ("status", "status"),
        ("state_json", "state_json"),
        ("last_heartbeat", "last_heartbeat"),
        ("last_ip", "last_ip"),
        ("created_at", "created_at"),
        ("updated_at", "updated_at"),
        ("is_active", "is_active"),
    )

    legacy_fields = (
        ("version", "legacy_version"),
        ("last_seen_at", "legacy_last_seen_at"),
        ("last_seen", "legacy_last_seen_at"),
        ("payload_json", "legacy_payload_json"),
        ("data_json", "legacy_payload_json"),
        (
            "audit_success_enabled",
            "legacy_audit_success_enabled",
        ),
        (
            "audit_failure_enabled",
            "legacy_audit_failure_enabled",
        ),
        ("audit_filter", "legacy_audit_filter"),
        ("audit_ready", "legacy_audit_ready"),
        (
            "capabilities_json",
            "legacy_capabilities_json",
        ),
        ("metadata_json", "legacy_metadata_json"),
        ("name", "legacy_name"),
    )

    if existing:
        if int(existing["environment_id"]) != int(environment_id):
            raise HTTPException(
                status_code=409,
                detail=("Agent key belongs to another environment"),
            )

        assignments = []

        for column, parameter in canonical_fields + legacy_fields:
            if column in schema and column != "agent_key":
                assignments.append(f'"{column}" = :{parameter}')

        db.execute(
            text("UPDATE monitoring_agents SET " + ", ".join(assignments) + " WHERE agent_key = :agent_key"),
            values,
        )

    else:
        insert_columns = []
        insert_parameters = []
        included_columns = set()

        def add_column(
            column: str,
            parameter: str,
            value,
        ) -> None:
            if column not in schema or column in included_columns:
                return

            values[parameter] = value
            insert_columns.append(f'"{column}"')
            insert_parameters.append(f":{parameter}")
            included_columns.add(column)

        for column, parameter in canonical_fields:
            add_column(
                column,
                parameter,
                values[parameter],
            )

        for column, parameter in legacy_fields:
            add_column(
                column,
                parameter,
                values[parameter],
            )

        def compatibility_value(
            column: str,
            type_name: str,
        ):
            normalized = column.lower()
            normalized_type = type_name.upper()

            if "version" in normalized:
                return agent_version

            if "environment" in normalized:
                return environment_id

            if "key" in normalized:
                return agent_key

            if "host" in normalized:
                return hostname

            if normalized in {
                "name",
                "server_name",
                "computer_name",
            }:
                return hostname

            if "ca_name" in normalized:
                return ca_name

            if "json" in normalized or "payload" in normalized or "state" in normalized:
                return state_json

            if "seen" in normalized or "time" in normalized or normalized.endswith("_at"):
                return now

            if "status" in normalized:
                return "online"

            if "INT" in normalized_type or "BOOL" in normalized_type:
                return 1

            if "REAL" in normalized_type or "FLOAT" in normalized_type or "DOUBLE" in normalized_type:
                return 0.0

            return agent_key

        for column, details in schema.items():
            if column in included_columns:
                continue

            if details["primary_key"]:
                continue

            if details["not_null"] and details["default"] is None:
                parameter = "legacy_required_" + str(len(insert_columns))

                add_column(
                    column,
                    parameter,
                    compatibility_value(
                        column,
                        details["type"],
                    ),
                )

        db.execute(
            text("INSERT INTO monitoring_agents (" + ", ".join(insert_columns) + ") VALUES (" + ", ".join(insert_parameters) + ")"),
            values,
        )

    db.commit()

    return dict(_agent_row(db, agent_key))


def get_agents(
    db: Session,
    environment_id: int | None,
) -> list[dict]:
    if not environment_id:
        return []

    rows = (
        db.execute(
            text("SELECT * FROM monitoring_agents " "WHERE environment_id = :environment_id " "AND is_active = 1 " "ORDER BY ca_name, hostname"),
            {"environment_id": environment_id},
        )
        .mappings()
        .all()
    )

    agents = []
    for row in rows:
        state = _load(row["state_json"], {})
        auditing = state.get("auditing") or {}
        heartbeat = _parse_time(row["last_heartbeat"])
        connected = bool(heartbeat and (_now() - heartbeat).total_seconds() <= CONNECTED_SECONDS)

        policy_enabled = bool(auditing.get("policy_enabled"))
        audit_filter = int(auditing.get("audit_filter") or 0)
        security_log_access = bool(auditing.get("security_log_access"))

        agents.append(
            {
                "id": int(row["id"]),
                "agent_key": row["agent_key"],
                "hostname": row["hostname"],
                "ca_name": row["ca_name"] or "",
                "agent_version": row["agent_version"] or "",
                "connected": connected,
                "last_heartbeat": str(row["last_heartbeat"] or ""),
                "last_ip": row["last_ip"] or "",
                "auditing": {
                    "policy_enabled": policy_enabled,
                    "audit_filter": audit_filter,
                    "security_log_access": (security_log_access),
                    "ready": (policy_enabled and audit_filter == 127 and security_log_access),
                    "gpo_managed": bool(auditing.get("gpo_managed")),
                    "message": str(auditing.get("message") or ""),
                },
                "services": state.get("services") or {},
                "resources": state.get("resources") or {},
                "sessions": state.get("sessions") or [],
                "web_activity": (state.get("web_activity") or []),
            }
        )

    return agents


def queue_command(
    db: Session,
    *,
    agent_id: int,
    environment_id: int,
    command_type: str,
    requested_by: str,
) -> int:
    if command_type not in ALLOWED_COMMANDS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported monitoring command",
        )

    agent = db.execute(
        text("SELECT id FROM monitoring_agents " "WHERE id = :id " "AND environment_id = :environment_id " "AND is_active = 1"),
        {
            "id": agent_id,
            "environment_id": environment_id,
        },
    ).scalar()

    if not agent:
        raise HTTPException(
            status_code=404,
            detail="Monitoring agent not found",
        )

    existing = db.execute(
        text("SELECT id FROM monitoring_commands " "WHERE agent_id = :agent_id " "AND command_type = :command_type " "AND status IN ('queued', 'running') " "ORDER BY id DESC LIMIT 1"),
        {
            "agent_id": agent_id,
            "command_type": command_type,
        },
    ).scalar()

    if existing:
        return int(existing)

    now = _now_text()

    table_info = db.execute(text("PRAGMA table_info(monitoring_commands)")).fetchall()

    schema = {
        row[1]: {
            "type": str(row[2] or ""),
            "not_null": bool(row[3]),
            "default": row[4],
            "primary_key": bool(row[5]),
        }
        for row in table_info
    }

    values = {
        "environment_id": environment_id,
        "agent_id": agent_id,
        "command_type": command_type,
        "status": "queued",
        "requested_by": requested_by,
        "requested_at": now,
        "result_json": "{}",
        "legacy_action": command_type,
        "legacy_created_at": now,
        "legacy_payload_json": "{}",
    }

    field_map = (
        ("environment_id", "environment_id"),
        ("agent_id", "agent_id"),
        ("command_type", "command_type"),
        ("status", "status"),
        ("requested_by", "requested_by"),
        ("requested_at", "requested_at"),
        ("result_json", "result_json"),
        ("action", "legacy_action"),
        ("command", "legacy_action"),
        ("created_at", "legacy_created_at"),
        ("payload_json", "legacy_payload_json"),
    )

    insert_columns = []
    insert_parameters = []
    included_columns = set()

    def add_column(
        column: str,
        parameter: str,
        value,
    ) -> None:
        if column not in schema or column in included_columns:
            return

        values[parameter] = value
        insert_columns.append(f'"{column}"')
        insert_parameters.append(f":{parameter}")
        included_columns.add(column)

    for column, parameter in field_map:
        add_column(
            column,
            parameter,
            values[parameter],
        )

    for column, details in schema.items():
        if column in included_columns:
            continue

        if details["primary_key"]:
            continue

        if details["not_null"] and details["default"] is None:
            normalized = column.lower()
            type_name = details["type"].upper()

            if "command" in normalized or "action" in normalized:
                fallback = command_type
            elif "environment" in normalized:
                fallback = environment_id
            elif "agent" in normalized:
                fallback = agent_id
            elif "user" in normalized or "request" in normalized:
                fallback = requested_by
            elif "json" in normalized or "payload" in normalized:
                fallback = "{}"
            elif "time" in normalized or normalized.endswith("_at"):
                fallback = now
            elif "status" in normalized:
                fallback = "queued"
            elif "INT" in type_name or "BOOL" in type_name:
                fallback = 0
            else:
                fallback = command_type

            parameter = "legacy_required_" + str(len(insert_columns))

            add_column(
                column,
                parameter,
                fallback,
            )

    cursor = db.execute(
        text("INSERT INTO monitoring_commands (" + ", ".join(insert_columns) + ") VALUES (" + ", ".join(insert_parameters) + ")"),
        values,
    )

    db.commit()

    return int(cursor.lastrowid)


def poll_command(
    db: Session,
    agent_key: str,
) -> dict | None:
    agent = _agent_row(db, agent_key)
    if not agent:
        raise HTTPException(
            status_code=404,
            detail="Monitoring agent not registered",
        )

    command = (
        db.execute(
            text("SELECT * FROM monitoring_commands " "WHERE agent_id = :agent_id " "AND status = 'queued' " "ORDER BY id LIMIT 1"),
            {"agent_id": agent["id"]},
        )
        .mappings()
        .first()
    )

    if not command:
        return None

    db.execute(
        text("UPDATE monitoring_commands SET " "status = 'running', picked_up_at = :now " "WHERE id = :id AND status = 'queued'"),
        {
            "now": _now_text(),
            "id": command["id"],
        },
    )
    db.commit()

    return {
        "id": int(command["id"]),
        "command_type": command["command_type"],
    }


def complete_command(
    db: Session,
    *,
    agent_key: str,
    command_id: int,
    success: bool,
    result: dict,
) -> None:
    agent = _agent_row(db, agent_key)
    if not agent:
        raise HTTPException(
            status_code=404,
            detail="Monitoring agent not registered",
        )

    command = db.execute(
        text("SELECT id FROM monitoring_commands " "WHERE id = :id AND agent_id = :agent_id"),
        {
            "id": command_id,
            "agent_id": agent["id"],
        },
    ).scalar()

    if not command:
        raise HTTPException(
            status_code=404,
            detail="Monitoring command not found",
        )

    db.execute(
        text("UPDATE monitoring_commands SET " "status = :status, completed_at = :completed_at, " "result_json = :result " "WHERE id = :id"),
        {
            "status": ("completed" if success else "failed"),
            "completed_at": _now_text(),
            "result": json.dumps(result or {}),
            "id": command_id,
        },
    )
    db.commit()


def latest_command_status(
    db: Session,
    agent_id: int,
) -> dict | None:
    row = (
        db.execute(
            text("SELECT * FROM monitoring_commands " "WHERE agent_id = :agent_id " "ORDER BY id DESC LIMIT 1"),
            {"agent_id": agent_id},
        )
        .mappings()
        .first()
    )
    if not row:
        return None
    return {
        "id": int(row["id"]),
        "command_type": row["command_type"],
        "status": row["status"],
        "requested_at": str(row["requested_at"] or ""),
        "completed_at": str(row["completed_at"] or ""),
        "result": _load(
            row["result_json"],
            {},
        ),
    }


def overlay_agent_state(
    db: Session,
    scan: Any,
    monitoring: dict,
) -> dict:
    environment_id = int(scan.environment_id) if scan and scan.environment_id else None
    agents = get_agents(db, environment_id)

    for agent in agents:
        agent["latest_command"] = latest_command_status(
            db,
            agent["id"],
        )

    monitoring["monitoring_agents"] = agents
    connected = [agent for agent in agents if agent["connected"]]
    monitoring["agent_connected"] = bool(connected)
    monitoring["mode"] = "live" if connected else "snapshot"
    monitoring["status"] = "live" if connected else "not_connected"
    monitoring["status_label"] = f"{len(connected)} monitoring agent" f"{'' if len(connected) == 1 else 's'} connected" if connected else "Monitoring agent not connected"

    if connected:
        monitoring["last_update"] = max(agent["last_heartbeat"] for agent in connected)
        counters = monitoring.setdefault(
            "counters",
            {},
        )
        counters["active_admins"] = sum(len(agent["sessions"]) for agent in connected)
        web_users = {str(item.get("username") or item.get("source_ip") or "") for agent in connected for item in agent["web_activity"] if (item.get("username") or item.get("source_ip"))}
        counters["web_users"] = len(web_users)

    readiness_alerts = []
    for agent in agents:
        if not agent["connected"]:
            readiness_alerts.append(
                {
                    "id": (f"agent-offline-{agent['id']}"),
                    "severity": "warning",
                    "title": ("Monitoring disconnected on " f"{agent['hostname']}"),
                    "summary": ("No recent heartbeat was received " "from this CA server."),
                    "impact": ("Live PKI activity is unavailable " "from this server."),
                    "target": "/pki-monitoring",
                }
            )
        elif not agent["auditing"]["ready"]:
            readiness_alerts.append(
                {
                    "id": (f"audit-not-ready-{agent['id']}"),
                    "severity": "warning",
                    "title": ("PKI auditing is not fully enabled " f"on {agent['hostname']}"),
                    "summary": ("Use Monitoring Readiness below " "to enable the required audit settings."),
                    "impact": ("Certificate request and issuance " "events may be missing."),
                    "target": "/pki-monitoring",
                }
            )

    monitoring["alerts"] = readiness_alerts + list(monitoring.get("alerts") or [])
    monitoring.setdefault(
        "counters",
        {},
    )["active_alerts"] = len(monitoring["alerts"])

    return monitoring
