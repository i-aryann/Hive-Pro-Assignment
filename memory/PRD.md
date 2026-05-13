# PRD — TawasolPay AI Cyber Risk Assistant

## Original Problem Statement
TawasolPay (Series B fintech, Dubai) needs an AI-Powered Cyber Risk Assistant that ingests their asset inventory, open vulnerability list, threat intel feeds, and business service context, then produces a prioritised, explainable Top-5 risk list with remediation guidance retrieved from the official NIST SP 800-53 Rev. 5 catalog. The system must (1) rank risks beyond CVSS (using internet exposure, exploit availability, threat campaign matches, business criticality, missing controls), (2) retrieve and surface NIST 800-53 remediation guidance from the actual NIST document (not LLM training data, not the one-liner remediation_guidance.csv), and (3) produce human-readable structured output. Public URL + GitHub repo + README (with data-split rationale, three failure modes, and one-day improvement) are required.

## User Choices
- Product: Web dashboard + FastAPI backend + README for assignment submission.
- Stack: Python FastAPI + React (TailwindCSS, Shadcn UI, dark Swiss/control-room aesthetic) + MongoDB + Qdrant Cloud free tier (env-ready, currently in local-text-fallback).
- Risk engine: Hybrid deterministic scoring + RAG-based NIST retrieval + LIVE CISA KEV cross-reference + optional LLM wording.
- Current data mode: Sample data placeholders clearly marked until real data pack is uploaded.
- LLM mode: Optional Gemini/Groq/OpenRouter key; current wording uses deterministic templates.

## Architecture Decisions
- FastAPI under `/api`: `/health`, `/risks/top`, `/nist/sync`, `/cisa-kev/sync`, `/threat-report`, `/data/upload`, `/data/sample`, `/nist/controls/{identifier}`.
- MongoDB collections: `assets`, `vulnerabilities`, `threat_intelligence`, `business_services`, `remediation_guidance`, `threat_reports`, `nist_controls`, `cisa_kev`.
- NIST guidance fetched live from CSRC CSV; per-control `source_url` returned to UI.
- CISA KEV catalog fetched live from cisa.gov; every vulnerability enriched on each scoring pass (date_added, knownRansomwareCampaignUse, requiredAction).
- Qdrant integration installed and env-ready; falls back to text search if `QDRANT_URL`/`QDRANT_API_KEY` not set.
- Risk scoring is deterministic and explainable across CVSS, internet exposure, exploit availability, CISA KEV, ransomware association, threat-campaign match, business criticality, customer-facing services, EDR status, controls, and age.
- React dashboard: dark Swiss/high-contrast control-room design with full data-testid coverage.

## Implemented
- Dashboard: metrics, ops console, MDR advisory collapsible panel, data upload, NIST sync, CISA KEV sync, Top-5 risk cards with scoring factors, KEV evidence, business context, internal hint, NIST guidance + source URL link.
- Backend: NIST sync (1189 controls loaded), CISA KEV sync (1590 entries loaded live), risk ranking with kev_evidence + remediation_hint, data-pack upload with normalization, sample-data reset that also clears threat_reports and remediation_guidance.
- README: run instructions, data-split answer, three failure modes with mitigations, one-day improvement, Qdrant setup.
- Testing: 6/6 backend pytest cases pass, frontend Playwright/screenshot validation passed against all new data-testids.

## Known Placeholder / MOCKED Areas
- MOCKED sample dataset is active until user uploads the real assignment CSV/MD files (5 assets / 6 vulns / 3 threat-intel / 5 services in placeholder mode vs. real pack's 60 / 114 / 40 / 20).
- MOCKED Qdrant mode: client installed and env-ready, but current runtime uses local-text-fallback because no Qdrant credentials were provided.
- MOCKED LLM mode: deterministic-template wording is active because no free-tier LLM key was provided.

## Changelog
- 2026-05-13: Aligned implementation with original assignment by adding live CISA KEV sync + per-risk enrichment, MDR advisory panel, remediation hint surfacing, NIST source-URL linking. Tests expanded to 6 pytest cases.
- Prior: MVP scaffold, NIST CSRC sync, deterministic scoring, dark dashboard, data upload, README.

## Prioritized Backlog
### P0
- Upload the real assignment data pack (six files) so dataset_mode flips to `uploaded`.
- Add Qdrant Cloud credentials (`QDRANT_URL`, `QDRANT_API_KEY`) and re-run `/api/nist/sync` to populate vectors.
- Push to a public GitHub repo and confirm a public preview URL is accessible.

### P1
- Add optional LLM wording provider (Groq / Gemini / OpenRouter) with strict grounding once a free-tier key is provided.
- Add CSV validation errors for missing columns and malformed rows.
- Add filters by service, owner, exposure, severity on the dashboard.

### P2
- Add downloadable board-brief / PDF export.
- Add audit history for repeated board-brief generation.
- Modularise `backend/server.py` into `routers/` + `services/`.

## Next Tasks
1. Receive real data pack and Qdrant credentials from user.
2. Re-run NIST + KEV sync and validate top-5 against the real 60-asset / 114-vuln dataset.
3. Connect Qdrant Cloud and verify mode flips from `local-text-fallback` to `qdrant`.
4. Optional: wire LLM wording for polished plain-English explanations.
