import sqlite3
from pathlib import Path

db_path = Path('migration_validation.db')
if db_path.exists():
    db_path.unlink()

conn = sqlite3.connect(db_path)
cur = conn.cursor()
cur.executescript(Path('migrations/001_init.sql').read_text())
conn.commit()

required_tables = ['users','scans','certificate_authorities','certificate_templates','template_permissions','issued_certificates','findings','audit_logs','schema_migrations']
for table in required_tables:
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
    assert cur.fetchone(), f'{table} table missing'

cur.execute("PRAGMA table_info(findings)")
finding_cols = {r[1] for r in cur.fetchall()}
for col in ['esc_category','confidence','coverage_state','trigger_conditions','remediation_steps_json','simulation_json']:
    assert col in finding_cols, f'findings.{col} missing'

print('schema validation ok')
conn.close()
db_path.unlink(missing_ok=True)
