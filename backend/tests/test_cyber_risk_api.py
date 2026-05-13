import os
from pathlib import Path

import pytest
import requests


# Assignment-critical API coverage: health, NIST sync, KEV sync, top risk ranking payload, threat report, data upload.
def _load_base_url() -> str:
    env_path = Path("/app/frontend/.env")
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if line.startswith("REACT_APP_BACKEND_URL="):
                return line.split("=", 1)[1].strip().rstrip("/")
    value = os.environ.get("REACT_APP_BACKEND_URL")
    if value:
        return value.rstrip("/")
    pytest.skip("REACT_APP_BACKEND_URL is not configured")


BASE_URL = _load_base_url()
API_BASE = f"{BASE_URL}/api"


@pytest.fixture(scope="session")
def api_client():
    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})
    return session


@pytest.fixture(scope="session")
def synced_nist(api_client):
    response = api_client.post(f"{API_BASE}/nist/sync", timeout=120)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["controls_loaded"] > 0
    return data


@pytest.fixture(scope="session")
def synced_kev(api_client):
    response = api_client.post(f"{API_BASE}/cisa-kev/sync", timeout=120)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["entries_loaded"] > 0
    assert "source_url" in data
    return data


# --- Health endpoint contract -------------------------------------------------
def test_health_contract_with_kev_status(api_client):
    response = api_client.get(f"{API_BASE}/health", timeout=30)
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "healthy"
    for key in ("dataset_mode", "nist_status", "qdrant_status", "llm_wording", "kev_status"):
        assert key in data, f"missing health key: {key}"

    kev = data["kev_status"]
    for key in ("entries_loaded", "source_url", "synced", "last_synced_at"):
        assert key in kev, f"missing kev_status field: {key}"
    assert isinstance(kev["entries_loaded"], int)
    assert isinstance(kev["synced"], bool)


# --- NIST sync ----------------------------------------------------------------
def test_sync_nist_returns_official_controls(synced_nist):
    assert synced_nist["controls_loaded"] > 0
    assert "csrc.nist.gov" in synced_nist["source_url"]


# --- CISA KEV sync ------------------------------------------------------------
def test_sync_cisa_kev_live_csv(synced_kev):
    assert synced_kev["entries_loaded"] > 0
    assert synced_kev["source_url"].startswith("https://www.cisa.gov")
    assert "message" in synced_kev


# --- Top risks payload --------------------------------------------------------
def test_top_5_risks_payload_with_kev_and_hints(api_client, synced_nist, synced_kev):
    response = api_client.get(f"{API_BASE}/risks/top?limit=5", timeout=60)
    assert response.status_code == 200

    data = response.json()

    # Top-level new fields
    assert "kev_status" in data
    assert "threat_report" in data  # nullable

    kev_status = data["kev_status"]
    assert kev_status.get("entries_loaded", 0) > 0

    risks = data.get("risks", [])
    assert len(risks) == 5

    required_fields = {
        "score",
        "severity",
        "asset",
        "vulnerability",
        "business_service",
        "scoring_factors",
        "explanation",
        "plain_english_explanation",
        "remediation_guidance",
        "remediation_hint",
        "kev_evidence",
    }

    observed_factor_text = []
    guidance_found = False
    kev_with_date_added = 0
    for risk in risks:
        missing = required_fields - set(risk.keys())
        assert not missing, f"risk missing fields: {missing}"
        assert isinstance(risk["score"], (int, float))
        assert isinstance(risk["scoring_factors"], list)
        observed_factor_text.extend(risk["scoring_factors"])
        if risk["remediation_guidance"]:
            guidance_found = True
        if risk["kev_evidence"]:
            assert "date_added" in risk["kev_evidence"]
            if risk["kev_evidence"].get("date_added"):
                kev_with_date_added += 1

    combined = " ".join(observed_factor_text).lower()
    for expected_signal in [
        "internet",
        "exploit",
        "kev",
        "campaign",
        "ransomware",
        "criticality",
        "edr",
    ]:
        assert expected_signal in combined

    assert guidance_found
    # After KEV sync, at least one risk's CVE should match KEV catalog with a date_added populated.
    assert kev_with_date_added >= 1, "Expected at least one risk with kev_evidence.date_added after KEV sync"


# --- Threat report endpoint ---------------------------------------------------
def test_threat_report_endpoint_contract(api_client):
    response = api_client.get(f"{API_BASE}/threat-report", timeout=30)
    assert response.status_code == 200
    data = response.json()
    assert "threat_report" in data
    # threat_report is nullable; if present it should be a dict
    if data["threat_report"] is not None:
        assert isinstance(data["threat_report"], dict)


# --- Data upload + sample reset ----------------------------------------------
SAMPLE_ASSETS = (
    "asset_id,name,asset_type,owner,criticality,public_exposure\n"
    "AST-TEST,Test Box,server,sec,critical,true\n"
)
SAMPLE_VULNS = (
    "vuln_id,asset_id,cve_id,cvss,exploited_in_wild\n"
    "V-TEST,AST-TEST,CVE-2021-44228,10.0,true\n"
)
SAMPLE_TI = (
    "threat_id,cve_id,campaign,active\n"
    "T-TEST,CVE-2021-44228,LogShellOps,true\n"
)
SAMPLE_SERVICES = (
    "service_id,name,owner,criticality\n"
    "SVC-TEST,Test Service,sec,critical\n"
)
SAMPLE_CONTROL_MAP = "asset_id,control_id\nAST-TEST,AC-2\n"
SAMPLE_THREAT_REPORT = "# Synthetic Threat Report\nTest body for pytest upload\n"


def test_data_upload_then_sample_reset(api_client):
    # Upload endpoint accepts a list of files under the "files" multipart field.
    files = [
        ("files", ("assets.csv", SAMPLE_ASSETS, "text/csv")),
        ("files", ("vulnerabilities.csv", SAMPLE_VULNS, "text/csv")),
        ("files", ("threat_intelligence.csv", SAMPLE_TI, "text/csv")),
        ("files", ("business_services.csv", SAMPLE_SERVICES, "text/csv")),
        ("files", ("remediation_guidance.csv", SAMPLE_CONTROL_MAP, "text/csv")),
        ("files", ("synthetic_threat_report.md", SAMPLE_THREAT_REPORT, "text/markdown")),
    ]
    upload_session = requests.Session()
    response = upload_session.post(f"{API_BASE}/data/upload", files=files, timeout=60)
    assert response.status_code == 200, response.text

    # health should reflect uploaded mode
    health = api_client.get(f"{API_BASE}/health", timeout=30).json()
    assert health["dataset_mode"].lower() == "uploaded", f"dataset_mode after upload: {health['dataset_mode']}"

    # threat-report should expose the uploaded markdown
    tr = api_client.get(f"{API_BASE}/threat-report", timeout=30).json()
    assert tr["threat_report"] is not None
    assert tr["threat_report"]["filename"] == "synthetic_threat_report.md"

    # Reset to placeholder
    reset = api_client.post(f"{API_BASE}/data/sample", timeout=30)
    assert reset.status_code == 200, reset.text

    health2 = api_client.get(f"{API_BASE}/health", timeout=30).json()
    assert health2["dataset_mode"] == "SAMPLE_DATA_PLACEHOLDER"
