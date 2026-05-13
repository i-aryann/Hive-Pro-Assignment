from __future__ import annotations

import csv
import hashlib
import io
import logging
import math
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
import asyncio
from typing import Any, Dict, List, Optional, Tuple
import requests
from dotenv import load_dotenv
from fastapi import APIRouter, FastAPI, File, HTTPException, UploadFile
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.cors import CORSMiddleware

try:
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, PointStruct, VectorParams
except Exception:  # pragma: no cover - optional until Qdrant env is added
    QdrantClient = None
    Distance = None
    PointStruct = None
    VectorParams = None


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

app = FastAPI(title="TawasolPay AI Cyber Risk Assistant")
api_router = APIRouter(prefix="/api")

NIST_CSV_URL = (
    "https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/"
    "800-53r5/NIST_SP-800-53_rev5_catalog_load.csv"
)
CISA_KEV_CSV_URL = (
    "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
)
QDRANT_COLLECTION = os.environ.get("QDRANT_COLLECTION", "nist_800_53_controls")
EMBED_DIMENSION = 128

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


class NistControl(BaseModel):
    model_config = ConfigDict(extra="ignore")

    identifier: str
    name: str
    control_text: str = ""
    discussion: str = ""
    related: str = ""
    source_url: str = NIST_CSV_URL


class RiskEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")

    rank: int
    risk_id: str
    score: float
    severity: str
    asset: Dict[str, Any]
    vulnerability: Dict[str, Any]
    matched_threat_intel: Optional[Dict[str, Any]] = None
    business_service: Dict[str, Any]
    scoring_factors: List[str]
    explanation: str
    plain_english_explanation: str
    remediation_hint: Optional[str] = None
    kev_evidence: Optional[Dict[str, Any]] = None
    remediation_guidance: List[NistControl] = Field(default_factory=list)
    nist_sync_required: bool = False


class RiskResponse(BaseModel):
    generated_at: str
    dataset_mode: str
    nist_status: Dict[str, Any]
    qdrant_status: Dict[str, Any]
    kev_status: Dict[str, Any]
    threat_report: Optional[Dict[str, Any]] = None
    risks: List[RiskEntry]




def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def clean_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"true", "yes", "y", "1", "kev", "available"}


def clean_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def clean_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except Exception:
        return default


def normalize_text(value: Any) -> str:
    return str(value or "").strip()


def get_first(row: Dict[str, Any], keys: List[str], default: Any = "") -> Any:
    lowered = {str(k).strip().lower(): v for k, v in row.items()}
    for key in keys:
        if key.lower() in lowered and lowered[key.lower()] not in (None, ""):
            return lowered[key.lower()]
    return default


def hash_embedding(text: str, dimension: int = EMBED_DIMENSION) -> List[float]:
    vector = [0.0] * dimension
    tokens = re.findall(r"[a-zA-Z0-9-]+", text.lower())
    for token in tokens:
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        bucket = int(digest[:8], 16) % dimension
        sign = -1.0 if int(digest[8:10], 16) % 2 else 1.0
        vector[bucket] += sign
    norm = math.sqrt(sum(v * v for v in vector)) or 1.0
    return [v / norm for v in vector]


def qdrant_client() -> Optional[Any]:
    qdrant_url = os.environ.get("QDRANT_URL")
    qdrant_key = os.environ.get("QDRANT_API_KEY")
    if not qdrant_url or not qdrant_key or QdrantClient is None:
        return None
    return QdrantClient(url=qdrant_url, api_key=qdrant_key, timeout=10)


def qdrant_status() -> Dict[str, Any]:
    configured = bool(os.environ.get("QDRANT_URL") and os.environ.get("QDRANT_API_KEY"))
    installed = QdrantClient is not None
    status = {
        "configured": configured,
        "client_installed": installed,
        "collection": QDRANT_COLLECTION,
        "mode": "qdrant" if configured and installed else "local-text-fallback",
    }
    if configured and installed:
        try:
            qc = qdrant_client()
            qc.get_collection(QDRANT_COLLECTION)
            status["connected"] = True
        except Exception as exc:
            status["connected"] = False
            status["message"] = str(exc)
    return status


def ensure_qdrant_collection(qc: Any) -> None:
    try:
        qc.get_collection(QDRANT_COLLECTION)
    except Exception:
        qc.create_collection(
            collection_name=QDRANT_COLLECTION,
            vectors_config=VectorParams(size=EMBED_DIMENSION, distance=Distance.COSINE),
        )


async def upsert_qdrant_controls(controls: List[Dict[str, Any]]) -> Dict[str, Any]:
    qc = qdrant_client()
    if not qc:
        return {"upserted": 0, "mode": "local-text-fallback"}
    ensure_qdrant_collection(qc)
    points = []
    for control in controls:
        text = " ".join(
            [
                normalize_text(control.get("identifier")),
                normalize_text(control.get("name")),
                normalize_text(control.get("control_text")),
                normalize_text(control.get("discussion")),
            ]
        )
        points.append(
            PointStruct(
                id=str(uuid.uuid5(uuid.NAMESPACE_URL, control["identifier"])),
                vector=hash_embedding(text),
                payload={
                    "identifier": control["identifier"],
                    "name": control.get("name", ""),
                    "text": text[:4000],
                    "source_url": NIST_CSV_URL,
                },
            )
        )
    for idx in range(0, len(points), 128):
        qc.upsert(collection_name=QDRANT_COLLECTION, points=points[idx : idx + 128])
    return {"upserted": len(points), "mode": "qdrant"}


async def get_dataset() -> Tuple[str, Dict[str, List[Dict[str, Any]]]]:
    assets = await db.assets.find({}, {"_id": 0}).to_list(10000)
    vulnerabilities = await db.vulnerabilities.find({}, {"_id": 0}).to_list(10000)
    threat_intel = await db.threat_intelligence.find({}, {"_id": 0}).to_list(10000)
    business_services = await db.business_services.find({}, {"_id": 0}).to_list(10000)
    if assets and vulnerabilities:
        return "uploaded", {
            "assets": assets,
            "vulnerabilities": vulnerabilities,
            "threat_intelligence": threat_intel,
            "business_services": business_services,
        }
    return "empty", {
        "assets": [],
        "vulnerabilities": [],
        "threat_intelligence": [],
        "business_services": [],
    }


async def kev_status() -> Dict[str, Any]:
    count = await db.cisa_kev.count_documents({})
    newest = await db.cisa_kev.find({}, {"_id": 0, "synced_at": 1}).sort("synced_at", -1).limit(1).to_list(1)
    return {
        "entries_loaded": count,
        "source_url": CISA_KEV_CSV_URL,
        "synced": count > 0,
        "last_synced_at": newest[0].get("synced_at") if newest else None,
    }


async def kev_lookup(cve_id: str) -> Optional[Dict[str, Any]]:
    if not cve_id:
        return None
    return await db.cisa_kev.find_one({"cve_id": cve_id.upper()}, {"_id": 0})


async def apply_kev_enrichment(vuln: Dict[str, Any]) -> Dict[str, Any]:
    entry = await kev_lookup(normalize_text(vuln.get("cve_id")))
    if not entry:
        return vuln
    vuln = dict(vuln)
    vuln["cisa_kev"] = True
    vuln["kev_date_added"] = entry.get("date_added")
    vuln["kev_required_action"] = entry.get("required_action")
    vuln["kev_known_ransomware_campaign_use"] = entry.get("known_ransomware_campaign_use", False)
    return vuln


async def get_remediation_hint(cve_id: str, asset_id: str) -> Optional[str]:
    if cve_id:
        doc = await db.remediation_guidance.find_one(
            {"$or": [{"cve_id": cve_id.upper()}, {"CVE": cve_id.upper()}, {"cve": cve_id.upper()}]},
            {"_id": 0},
        )
        if doc:
            for key in ["hint", "remediation", "guidance", "recommendation", "summary", "description", "action"]:
                value = doc.get(key)
                if value:
                    return normalize_text(value)
            for key, value in doc.items():
                if isinstance(value, str) and len(value) > 8 and key not in {"cve_id", "asset_id"}:
                    return value
    if asset_id:
        doc = await db.remediation_guidance.find_one({"asset_id": asset_id}, {"_id": 0})
        if doc:
            for key in ["hint", "remediation", "guidance", "recommendation", "summary", "description", "action"]:
                value = doc.get(key)
                if value:
                    return normalize_text(value)
    return None


def service_weight(service: Dict[str, Any]) -> float:
    impact = normalize_text(service.get("revenue_impact")).lower()
    if impact in {"very_high", "very high", "critical"}:
        return 20
    if impact == "high":
        return 14
    if impact == "medium":
        return 8
    return 3


def criticality_weight(asset: Dict[str, Any]) -> float:
    criticality = normalize_text(asset.get("criticality")).lower()
    return {"critical": 18, "high": 12, "medium": 6, "low": 2}.get(criticality, 4)


def severity(score: float) -> str:
    if score >= 105:
        return "critical"
    if score >= 82:
        return "high"
    if score >= 58:
        return "medium"
    return "low"


def match_control_ids(asset: Dict[str, Any], vuln: Dict[str, Any], threat: Optional[Dict[str, Any]]) -> List[str]:
    text = " ".join([normalize_text(v) for v in [asset, vuln, threat] if v])
    ids = ["RA-5", "SI-2"]
    if "internet" in normalize_text(asset.get("exposure")).lower():
        ids.append("SC-7")
    if threat and clean_bool(threat.get("ransomware_association")):
        ids.extend(["IR-4", "CP-9"])
    if normalize_text(asset.get("edr_status")).lower() in {"missing", "degraded", "disabled"}:
        ids.extend(["SI-3", "SI-4"])
    if "vpn" in text.lower() or "auth" in text.lower() or "account" in text.lower():
        ids.append("AC-2")
    if "unsupported" in text.lower() or "end of life" in text.lower() or "eol" in text.lower():
        ids.append("SA-22")
    return list(dict.fromkeys(ids))[:5]


def score_risk(
    asset: Dict[str, Any],
    vuln: Dict[str, Any],
    threat: Optional[Dict[str, Any]],
    service: Dict[str, Any],
) -> Tuple[float, List[str]]:
    score = clean_float(vuln.get("cvss")) * 6
    factors = [f"CVSS {clean_float(vuln.get('cvss')):.1f} contributes base technical severity"]
    if normalize_text(asset.get("exposure")).lower() == "internet":
        score += 22
        factors.append("Internet-exposed asset increases attacker reachability")
    if clean_bool(vuln.get("exploit_available")):
        score += 18
        factors.append("Public exploit availability raises likelihood")
    if clean_bool(vuln.get("cisa_kev")):
        score += 14
        factors.append("CISA KEV flag indicates known exploitation")
    if clean_bool(vuln.get("kev_known_ransomware_campaign_use")):
        score += 8
        factors.append("CISA KEV flags known ransomware-campaign use")
    if threat:
        score += 24
        factors.append(f"Matched active campaign: {threat.get('campaign', 'threat intel match')}")
        if clean_bool(threat.get("ransomware_association")):
            score += 10
            factors.append("Ransomware association increases board-level urgency")
    score += criticality_weight(asset)
    factors.append(f"{normalize_text(asset.get('criticality')).title() or 'Unknown'} asset criticality")
    score += service_weight(service)
    if clean_bool(service.get("customer_facing")):
        score += 8
        factors.append("Customer-facing business service blast radius")
    days_open = clean_int(vuln.get("days_open"))
    if days_open > 60:
        score += 9
        factors.append(f"Vulnerability has remained open for {days_open} days")
    elif days_open > 30:
        score += 5
        factors.append(f"Vulnerability age is {days_open} days")
    if normalize_text(asset.get("edr_status")).lower() in {"missing", "degraded", "disabled"}:
        score += 12
        factors.append(f"EDR status is {asset.get('edr_status')}")
    controls = asset.get("compensating_controls") or []
    if isinstance(controls, str):
        controls = [c.strip() for c in controls.split(";") if c.strip()]
    if not controls:
        score += 7
        factors.append("No documented compensating controls")
    if not clean_bool(vuln.get("patch_available")):
        score += 6
        factors.append("No patch available, requiring compensating controls")
    return round(score, 1), factors[:7]


async def nist_status() -> Dict[str, Any]:
    count = await db.nist_controls.count_documents({})
    newest = await db.nist_controls.find({}, {"_id": 0, "synced_at": 1}).sort("synced_at", -1).limit(1).to_list(1)
    return {
        "controls_loaded": count,
        "source_url": NIST_CSV_URL,
        "synced": count > 0,
        "last_synced_at": newest[0].get("synced_at") if newest else None,
    }


async def find_nist_guidance(control_ids: List[str], query: str) -> Tuple[List[NistControl], bool]:
    loaded = await db.nist_controls.count_documents({})
    if not loaded:
        return [], True

    controls: List[Dict[str, Any]] = []
    if control_ids:
        controls = await db.nist_controls.find(
            {"identifier": {"$in": control_ids}}, {"_id": 0}
        ).to_list(10)
        controls.sort(key=lambda item: control_ids.index(item["identifier"]) if item["identifier"] in control_ids else 999)

    if len(controls) < 2:
        qc = qdrant_client()
        if qc:
            try:
                hits = qc.search(
                    collection_name=QDRANT_COLLECTION,
                    query_vector=hash_embedding(query),
                    limit=3,
                )
                identifiers = [hit.payload.get("identifier") for hit in hits if hit.payload]
                more = await db.nist_controls.find(
                    {"identifier": {"$in": identifiers}}, {"_id": 0}
                ).to_list(3)
                controls.extend([c for c in more if c.get("identifier") not in {x.get("identifier") for x in controls}])
            except Exception as exc:
                logger.warning("Qdrant search failed, using text fallback: %s", exc)

    if len(controls) < 2:
        terms = [term for term in re.findall(r"[A-Za-z]{4,}", query.lower())[:8]]
        if terms:
            regex = "|".join(re.escape(term) for term in terms)
            more = await db.nist_controls.find(
                {"$or": [{"name": {"$regex": regex, "$options": "i"}}, {"control_text": {"$regex": regex, "$options": "i"}}]},
                {"_id": 0},
            ).limit(3).to_list(3)
            controls.extend([c for c in more if c.get("identifier") not in {x.get("identifier") for x in controls}])

    return [NistControl(**control) for control in controls[:3]], False


async def generate_llm_explanation(context_text: str) -> str:
    api_key = os.environ.get("LLM_API_KEY")
    if not api_key:
        return context_text
        
    prompt = (
        "You are a Cyber Risk Assistant. "
        "Explain the following risk context in one short, non-technical paragraph "
        "suitable for a board member or executive. "
        "Do not use markdown formatting. Just output the text.\n\n"
        f"Context: {context_text}"
    )
    
    try:
        import litellm
        response = await litellm.acompletion(
            model="groq/llama3-8b-8192",
            messages=[{"role": "user", "content": prompt}],
            api_key=api_key,
            max_tokens=150,
            temperature=0.4
        )
        return response.choices[0].message.content.strip()
    except Exception as exc:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"LLM explanation failed: {exc}")
        return context_text


async def analyze_top_risks(limit: int = 5) -> RiskResponse:
    dataset_mode, dataset = await get_dataset()
    assets = {normalize_text(asset.get("asset_id") or asset.get("id")): asset for asset in dataset["assets"]}
    services = {normalize_text(svc.get("service") or svc.get("name")): svc for svc in dataset["business_services"]}
    threats = {normalize_text(ti.get("cve_id") or ti.get("cve") or ti.get("CVE")): ti for ti in dataset["threat_intelligence"]}
    candidates: List[Tuple[float, Dict[str, Any], Dict[str, Any], Optional[Dict[str, Any]], Dict[str, Any], List[str]]] = []

    for raw_vuln in dataset["vulnerabilities"]:
        vuln = normalize_vulnerability(raw_vuln)
        vuln = await apply_kev_enrichment(vuln)
        asset_id = normalize_text(vuln.get("asset_id"))
        asset = normalize_asset(assets.get(asset_id, {}))
        if not asset:
            continue
        service = services.get(normalize_text(asset.get("service")), {"service": asset.get("service", "Unknown")})
        threat = threats.get(normalize_text(vuln.get("cve_id")))
        score, factors = score_risk(asset, vuln, threat, service)
        candidates.append((score, asset, vuln, threat, service, factors))

    candidates.sort(key=lambda item: item[0], reverse=True)
    risks: List[RiskEntry] = []
    for rank, (score, asset, vuln, threat, service, factors) in enumerate(candidates[:limit], start=1):
        control_ids = match_control_ids(asset, vuln, threat)
        query = " ".join([vuln.get("description", ""), asset.get("type", ""), service.get("service", ""), " ".join(factors)])
        guidance, sync_required = await find_nist_guidance(control_ids, query)
        service_name = service.get("service") or asset.get("service", "Unknown service")
        threat_clause = (
            f" and is tied to {threat.get('campaign')}" if threat else " without a confirmed campaign match"
        )
        explanation = (
            f"{asset.get('hostname')} ranks #{rank} because {vuln.get('cve_id')} affects a "
            f"{asset.get('exposure')} {asset.get('environment')} asset supporting {service_name}{threat_clause}; "
            f"business criticality and missing/weak controls push it above CVSS-only ordering."
        )
        hint = await get_remediation_hint(normalize_text(vuln.get("cve_id")), normalize_text(asset.get("asset_id")))
        kev_evidence = None
        if vuln.get("cisa_kev") or vuln.get("kev_date_added"):
            kev_evidence = {
                "in_kev": True,
                "date_added": vuln.get("kev_date_added"),
                "required_action": vuln.get("kev_required_action"),
                "known_ransomware_campaign_use": vuln.get("kev_known_ransomware_campaign_use", False),
                "source_url": CISA_KEV_CSV_URL,
            }
        risks.append(
            RiskEntry(
                rank=rank,
                risk_id=f"RISK-{rank:02d}",
                score=score,
                severity=severity(score),
                asset=asset,
                vulnerability=vuln,
                matched_threat_intel=threat,
                business_service=service,
                scoring_factors=factors,
                explanation=explanation,
                plain_english_explanation=await generate_llm_explanation(explanation),
                remediation_hint=hint,
                kev_evidence=kev_evidence,
                remediation_guidance=guidance,
                nist_sync_required=sync_required,
            )
        )
    latest_report = await db.threat_reports.find({}, {"_id": 0}).sort("uploaded_at", -1).limit(1).to_list(1)
    return RiskResponse(
        generated_at=now_iso(),
        dataset_mode=dataset_mode,
        nist_status=await nist_status(),
        qdrant_status=qdrant_status(),
        kev_status=await kev_status(),
        threat_report=latest_report[0] if latest_report else None,
        risks=risks,
    )


def normalize_asset(row: Dict[str, Any]) -> Dict[str, Any]:
    if not row:
        return {}
    controls = get_first(row, ["compensating_controls", "controls", "security_controls"], [])
    if isinstance(controls, str):
        controls = [part.strip() for part in re.split(r"[,;|]", controls) if part.strip()]
    return {
        **row,
        "asset_id": normalize_text(get_first(row, ["asset_id", "asset id", "id", "asset"])),
        "hostname": normalize_text(get_first(row, ["hostname", "host", "asset_name", "name"], row.get("asset_id"))),
        "type": normalize_text(get_first(row, ["type", "asset_type", "category"], "Unknown")),
        "environment": normalize_text(get_first(row, ["environment", "env"], "unknown")),
        "owner": normalize_text(get_first(row, ["owner", "team"], "Unassigned")),
        "service": normalize_text(get_first(row, ["service", "business_service", "business service"], "Unknown")),
        "exposure": normalize_text(get_first(row, ["exposure", "internet_exposure", "internet exposure"], "internal")).lower(),
        "criticality": normalize_text(get_first(row, ["criticality", "business_criticality"], "medium")).lower(),
        "edr_status": normalize_text(get_first(row, ["edr_status", "edr", "endpoint_detection"], "unknown")).lower(),
        "compensating_controls": controls,
        "vendor_product": normalize_text(get_first(row, ["vendor_product", "product", "vendor/product", "version"], "")),
    }


def normalize_vulnerability(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        **row,
        "vuln_id": normalize_text(get_first(row, ["vuln_id", "id", "finding_id"], str(uuid.uuid4())[:8])),
        "asset_id": normalize_text(get_first(row, ["asset_id", "asset id", "asset", "host_id"])),
        "cve_id": normalize_text(get_first(row, ["cve_id", "cve", "CVE ID"])).upper(),
        "cvss": clean_float(get_first(row, ["cvss", "cvss_score", "score"], 0)),
        "exploit_available": clean_bool(get_first(row, ["exploit_available", "exploit", "public_exploit"], False)),
        "patch_available": clean_bool(get_first(row, ["patch_available", "patch", "fix_available"], False)),
        "days_open": clean_int(get_first(row, ["days_open", "age", "days"], 0)),
        "cisa_kev": clean_bool(get_first(row, ["cisa_kev", "kev", "known_exploited"], False)),
        "description": normalize_text(get_first(row, ["description", "summary", "title"], "Open vulnerability")),
    }


def parse_csv_bytes(content: bytes) -> List[Dict[str, Any]]:
    text = content.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    return [{k.strip(): v for k, v in row.items() if k is not None} for row in reader]


async def replace_collection(collection_name: str, docs: List[Dict[str, Any]]) -> int:
    await db[collection_name].delete_many({})
    if docs:
        await db[collection_name].insert_many(docs)
    return len(docs)


@api_router.get("/health")
async def health() -> Dict[str, Any]:
    dataset_mode, dataset = await get_dataset()
    return {
        "status": "healthy",
        "app": "TawasolPay AI Cyber Risk Assistant",
        "dataset_mode": dataset_mode,
        "counts": {key: len(value) for key, value in dataset.items()},
        "nist_status": await nist_status(),
        "qdrant_status": qdrant_status(),
        "kev_status": await kev_status(),
        "llm_wording": "env-ready" if os.environ.get("LLM_API_KEY") else "deterministic-template",
    }


@api_router.get("/threat-report")
async def get_threat_report() -> Dict[str, Any]:
    latest = await db.threat_reports.find({}, {"_id": 0}).sort("uploaded_at", -1).limit(1).to_list(1)
    return {"threat_report": latest[0] if latest else None}


@api_router.post("/cisa-kev/sync")
async def sync_cisa_kev() -> Dict[str, Any]:
    try:
        response = requests.get(CISA_KEV_CSV_URL, timeout=30)
        response.raise_for_status()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Unable to retrieve CISA KEV CSV: {exc}") from exc

    entries = []
    reader = csv.DictReader(io.StringIO(response.text))
    for row in reader:
        cve = normalize_text(get_first(row, ["cveID", "cve_id", "cveid"]))
        if not cve:
            continue
        entries.append(
            {
                "cve_id": cve.upper(),
                "vendor_project": normalize_text(get_first(row, ["vendorProject", "vendor", "vendor_project"])),
                "product": normalize_text(get_first(row, ["product"])),
                "vulnerability_name": normalize_text(get_first(row, ["vulnerabilityName", "name"])),
                "date_added": normalize_text(get_first(row, ["dateAdded", "date_added"])),
                "required_action": normalize_text(get_first(row, ["requiredAction", "required_action"])),
                "known_ransomware_campaign_use": clean_bool(
                    get_first(row, ["knownRansomwareCampaignUse", "known_ransomware_campaign_use"], "")
                ),
                "due_date": normalize_text(get_first(row, ["dueDate", "due_date"])),
                "notes": normalize_text(get_first(row, ["notes"])),
                "source_url": CISA_KEV_CSV_URL,
                "synced_at": now_iso(),
            }
        )
    await db.cisa_kev.delete_many({})
    if entries:
        await db.cisa_kev.insert_many(entries)
    return {
        "message": "CISA KEV catalog synced",
        "entries_loaded": len(entries),
        "source_url": CISA_KEV_CSV_URL,
    }





@api_router.post("/data/upload")
async def upload_data_pack(files: List[UploadFile] = File(...)) -> Dict[str, Any]:
    mapping = {
        "assets": "assets",
        "vulnerabilities": "vulnerabilities",
        "threat_intelligence": "threat_intelligence",
        "business_services": "business_services",
        "remediation_guidance": "remediation_guidance",
    }
    loaded: Dict[str, int] = {}
    for uploaded in files:
        filename = uploaded.filename or ""
        stem = Path(filename).stem.lower()
        content = await uploaded.read()
        if filename.endswith(".md") or stem == "synthetic_threat_report":
            await db.threat_reports.delete_many({"filename": filename})
            await db.threat_reports.insert_one({"filename": filename, "content": content.decode("utf-8", errors="replace"), "uploaded_at": now_iso()})
            loaded["synthetic_threat_report"] = 1
            continue
        target = next((collection for key, collection in mapping.items() if key in stem), None)
        if not target:
            continue
        docs = parse_csv_bytes(content)
        if target == "assets":
            docs = [normalize_asset(doc) for doc in docs]
        elif target == "vulnerabilities":
            docs = [normalize_vulnerability(doc) for doc in docs]
        loaded[target] = await replace_collection(target, docs)
    if not loaded:
        raise HTTPException(status_code=400, detail="No recognized data-pack files were uploaded.")
    return {"message": "Data pack ingested", "loaded": loaded, "dataset_mode": "uploaded"}


@api_router.get("/nist/status")
async def get_nist_status() -> Dict[str, Any]:
    return {"nist_status": await nist_status(), "qdrant_status": qdrant_status()}


@api_router.post("/nist/sync")
async def sync_nist_controls() -> Dict[str, Any]:
    try:
        response = requests.get(NIST_CSV_URL, timeout=30)
        response.raise_for_status()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Unable to retrieve NIST CSV: {exc}") from exc

    controls = []
    reader = csv.DictReader(io.StringIO(response.text))
    for row in reader:
        identifier = normalize_text(row.get("identifier"))
        if not identifier:
            continue
        controls.append(
            {
                "identifier": identifier,
                "name": normalize_text(row.get("name")),
                "control_text": normalize_text(row.get("control_text")),
                "discussion": normalize_text(row.get("discussion")),
                "related": normalize_text(row.get("related")),
                "source_url": NIST_CSV_URL,
                "synced_at": now_iso(),
            }
        )
    await db.nist_controls.delete_many({})
    if controls:
        await db.nist_controls.insert_many(controls)
    qdrant_result = await upsert_qdrant_controls(controls)
    return {
        "message": "Official NIST SP 800-53 Rev. 5 controls synced",
        "controls_loaded": len(controls),
        "source_url": NIST_CSV_URL,
        "qdrant": qdrant_result,
    }


@api_router.get("/risks/top", response_model=RiskResponse)
async def top_risks(limit: int = 5) -> RiskResponse:
    return await analyze_top_risks(limit=max(1, min(limit, 10)))


@api_router.get("/nist/controls/{identifier}", response_model=NistControl)
async def get_control(identifier: str) -> NistControl:
    control = await db.nist_controls.find_one({"identifier": identifier.upper()}, {"_id": 0})
    if not control:
        raise HTTPException(status_code=404, detail="Control not found. Sync NIST controls first.")
    return NistControl(**control)


@api_router.get("/")
async def root() -> Dict[str, str]:
    return {"message": "TawasolPay AI Cyber Risk Assistant API"}


app.include_router(api_router)

cors_origins = os.environ.get("CORS_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_credentials="*" not in cors_origins,
    allow_origins=cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("shutdown")
async def shutdown_db_client() -> None:
    client.close()