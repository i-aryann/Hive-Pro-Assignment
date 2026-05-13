# TawasolPay AI Cyber Risk Assistant

Working FastAPI + React dashboard for the take-home assignment: it ranks the top 5 cyber risks using asset exposure, exploitability, threat-intelligence matches, business criticality, missing controls, and vulnerability age. It also retrieves remediation guidance from the official NIST SP 800-53 Rev. 5 CSV source and is ready to push controls into Qdrant Cloud when `QDRANT_URL` and `QDRANT_API_KEY` are added.

## What is implemented

- Web dashboard with top-5 ranked risks, evidence, score factors, threat matches, MDR advisory display, and NIST remediation panels.
- FastAPI endpoints for health, risk ranking, official NIST sync, **live CISA KEV sync and cross-reference**, Qdrant-ready vector upsert/search, sample data mode, and real data-pack upload.
- KEV enrichment on every risk: vulnerabilities are cross-referenced live against the CISA KEV catalog (`cveID`, `dateAdded`, `knownRansomwareCampaignUse`, `requiredAction`) and surfaced as evidence.
- `remediation_guidance.csv` hints are stored and surfaced inline with the official NIST control as a starting point (clearly labelled as a hint, not the answer).
- Each NIST control card links back to the official CSRC source URL it was retrieved from.
- `synthetic_threat_report.md` is ingested and rendered as a collapsible MDR advisory panel.
- SAMPLE_DATA_PLACEHOLDER records are active until the real six files are uploaded.
- Optional LLM wording is env-ready, but the current build uses deterministic plain-English templates so it works without paid services.

## Run locally

Backend:

```bash
cd backend
pip install -r requirements.txt
uvicorn server:app --host 0.0.0.0 --port 8001
```

Frontend:

```bash
cd frontend
yarn install
yarn start

```

Required environment variables:

- `backend/.env`: `MONGO_URL`, `DB_NAME`, optional `QDRANT_URL`, optional `QDRANT_API_KEY`, optional `QDRANT_COLLECTION`, optional `LLM_API_KEY`.
- `frontend/.env`: `REACT_APP_BACKEND_URL`.

## Main API endpoints

- `GET /api/health` — service, dataset, NIST, CISA KEV, Qdrant, and LLM-mode status.
- `POST /api/nist/sync` — retrieves official NIST SP 800-53 Rev. 5 controls from CSRC CSV and upserts to Qdrant if credentials exist.
- `POST /api/cisa-kev/sync` — retrieves the live CISA Known Exploited Vulnerabilities catalog and enriches every subsequent risk evaluation.
- `GET /api/threat-report` — returns the most recently uploaded `synthetic_threat_report.md` content.
- `GET /api/risks/top?limit=5` — ranked, explainable risk list with KEV evidence, remediation hint, and NIST remediation guidance.
- `POST /api/data/upload` — accepts the assignment files: `assets.csv`, `vulnerabilities.csv`, `threat_intelligence.csv`, `business_services.csv`, `remediation_guidance.csv`, and `synthetic_threat_report.md`.
- `POST /api/data/sample` — clears uploaded data and returns to sample data mode.

## Data split decision

Structured records such as assets, vulnerabilities, threat intelligence, and business services are queried as structured data because ranking needs exact joins, booleans, numeric CVSS scores, internet exposure flags, CISA KEV flags, and business criticality. Keeping these in MongoDB-style collections makes the scoring explainable and auditable instead of relying on fuzzy retrieval for facts.

NIST SP 800-53 control text is embedded/vectorized because remediation guidance is long-form reference material where semantic retrieval is useful. The system first retrieves exact likely control IDs such as `SI-2`, `RA-5`, `IR-4`, `SC-7`, and then can fall back to Qdrant/vector or text search over the official NIST CSV content.

## Where the system can go wrong

1. **False threat matches by CVE only:** If a campaign references a CVE but not TawasolPay's exact product/version or exposure path, the risk can be overstated. Mitigation: show the matched threat intel explicitly and keep the scoring factors visible for reviewer challenge.
2. **CISA KEV and ransomware fields may be stale:** The uploaded vulnerability file may mark KEV incorrectly or lag the live CISA catalog. Mitigation: the model isolates the KEV factor and can be extended to refresh CISA KEV live before scoring.
3. **NIST retrieval can select a relevant but incomplete control:** For example, `RA-5` may be generally relevant while `SI-2` is more actionable for patching. Mitigation: the system returns multiple controls per risk and records the official source URL so recommendations can be validated.

## One improvement with an extra day

The most important improvement would be adding live CISA KEV synchronization and richer validation against vendor/product/version fields before scoring. That would reduce false positives, strengthen ransomware-specific prioritization, and make the final board briefing more defensible because exploit and campaign evidence would be confirmed against current public intelligence, not only the uploaded CSV.

## Qdrant setup

Create a free Qdrant Cloud cluster, then add these backend environment variables:

```bash
QDRANT_URL=https://your-cluster-url
QDRANT_API_KEY=your-api-key
QDRANT_COLLECTION=nist_800_53_controls
```

After adding them, restart the backend and call `POST /api/nist/sync`. The system will create the collection if needed and upsert official NIST control vectors.