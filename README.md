# TrustGate

Layered scam & impersonation risk verification **before money moves**.

> Work in progress for ForgeHacks Online 2026 (AI + Cybersecurity track). Full documentation lands with the final phase.

## Quick start (development)

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt && pip install -e .
python scripts/download_data.py   # ~50 MB of open datasets into data/ (git-ignored)
pytest
```
