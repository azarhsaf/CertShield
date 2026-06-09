import sqlite3
from pathlib import Path

db_path = Path('migration_validation.db')
if db_path.exists():
    db_path.unlink()

conn = sqlite3.connect(db_path)
cur = conn.cursor()
cur.executescript(Path('migrations/001_init.sql').read_text())
conn.commit()

required_tables = ['users','scans','certificate_authorities','certificate_templates','template_permissions','issued_certificates','findings','audit_logs','schema_migrations','risk_acceptances']
for table in required_tables:
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
    assert cur.fetchone(), f'{table} table missing'

cur.execute("PRAGMA table_info(findings)")
finding_cols = {r[1] for r in cur.fetchall()}
for col in ['esc_category','confidence','coverage_state','trigger_conditions','remediation_steps_json','simulation_json']:
    assert col in finding_cols, f'findings.{col} missing'

cur.execute("PRAGMA table_info(risk_acceptances)")
risk_acceptance_cols = {r[1] for r in cur.fetchall()}
for col in ['fingerprint','object_type','object_name','category','risk_title','accepted_by','expiry_date','business_justification','compensating_control','status','scope']:
    assert col in risk_acceptance_cols, f'risk_acceptances.{col} missing'

print('schema validation ok')
conn.close()
db_path.unlink(missing_ok=True)
