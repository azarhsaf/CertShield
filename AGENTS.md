# CertShield Repository Instructions

Read `docs/CERTSHIELD_CURRENT_STATE.md` before modifying the collector,
assessment registry, evidence gaps, posture scoring, or upgrade scripts.

Preserve these rules:

- Never convert unavailable evidence into Pass.
- Keep confirmed findings separate from evidence gaps.
- Do not create one manual-governance gap per asset.
- Upgrade mode must preserve existing customer data.
- Clean-install mode must require explicit selection.
- Do not commit runtime data, secrets, certificates, or private keys.
- Run `pytest -q` and `python -m ruff check app tests` before committing.
