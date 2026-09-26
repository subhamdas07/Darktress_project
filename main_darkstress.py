"""
Dark Web Monitoring System — Module 1
Threat Intelligence Platform & Investigation

Every endpoint lives directly in this file (models/schemas/services stay
in their own modules under app/). Run locally:

    uvicorn app.main:app --reload --port 8000
"""

import uuid

from fastapi import Depends, FastAPI, HTTPException, Request, UploadFile, File, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.logging_config import setup_logging
from app.core.security import (
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from app.core.service_auth import verify_ingestion_key
from app.models.investigation import Alert, Case, EvidenceRecord, Investigation
from app.models.user import User
from app.schemas.auth import Token, UserCreate, UserOut
from app.schemas.ingestion import DocumentIngest, EntityIngest, RelationshipIngest
from app.schemas.investigation import (
    AlertCreate,
    AlertOut,
    CaseCreate,
    CaseOut,
    EvidenceOut,
    InvestigationCreate,
    InvestigationOut,
)
from app.services import blockchain_client, elasticsearch_client, evidence_store, neo4j_client, siem_client

setup_logging()

app = FastAPI(
    title="Dark Web Monitoring System — Module 1",
    description="Threat Intelligence Platform & Investigation backend",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_auth = Depends(get_current_user)


# =========================================================================
# System
# =========================================================================

@app.get("/", tags=["System"])
async def root():
    return {
        "service": "Dark Web Monitoring System — Module 1",
        "status": "running",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health", tags=["System"])
async def health_check():
    return {"status": "ok", "service": "dark-web-monitor-module1"}


# =========================================================================
# Auth  (open — issues the JWT everything else below requires)
# =========================================================================

@app.post("/api/v1/auth/register", response_model=UserOut, status_code=status.HTTP_201_CREATED, tags=["Auth"])
async def register(payload: UserCreate, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(
        select(User).where((User.username == payload.username) | (User.email == payload.email))
    )
    if existing.scalars().first():
        raise HTTPException(status_code=400, detail="Username or email already registered")

    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@app.post("/api/v1/auth/token", response_model=Token, tags=["Auth"])
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == form_data.username))
    user = result.scalars().first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is inactive")

    access_token = create_access_token(subject=str(user.id))
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/api/v1/auth/me", response_model=UserOut, tags=["Auth"])
async def get_me(current_user: User = _auth):
    return current_user


# =========================================================================
# Investigator — cases, investigations, cross-source search  (JWT required)
# =========================================================================

@app.post("/api/v1/investigator/cases", response_model=CaseOut, tags=["Investigator"])
async def create_case(payload: CaseCreate, db: AsyncSession = Depends(get_db), user: User = _auth):
    case = Case(title=payload.title, description=payload.description)
    db.add(case)
    await db.commit()
    await db.refresh(case)
    return case


@app.get("/api/v1/investigator/cases", response_model=list[CaseOut], tags=["Investigator"])
async def list_cases(db: AsyncSession = Depends(get_db), user: User = _auth):
    result = await db.execute(select(Case))
    return result.scalars().all()


@app.get("/api/v1/investigator/cases/{case_id}", response_model=CaseOut, tags=["Investigator"])
async def get_case(case_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: User = _auth):
    case = await db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@app.post("/api/v1/investigator/investigations", response_model=InvestigationOut, tags=["Investigator"])
async def create_investigation(
    payload: InvestigationCreate, db: AsyncSession = Depends(get_db), user: User = _auth
):
    case = await db.get(Case, payload.case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    investigation = Investigation(case_id=payload.case_id, query=payload.query)
    db.add(investigation)
    await db.commit()
    await db.refresh(investigation)
    return investigation


@app.get("/api/v1/investigator/investigations/{investigation_id}/search", tags=["Investigator"])
async def cross_source_search(
    investigation_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: User = _auth
):
    """Runs the investigation's query against Elasticsearch and Neo4j, returns combined results."""
    investigation = await db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    content_hits = await elasticsearch_client.search_documents("posts", investigation.query)
    graph_hits = await neo4j_client.run_query(
        "MATCH (n) WHERE n.alias CONTAINS $q OR n.id = $q RETURN n LIMIT 25",
        {"q": investigation.query},
    )

    return {
        "investigation_id": investigation_id,
        "query": investigation.query,
        "content_matches": content_hits,
        "graph_matches": graph_hits,
    }


# =========================================================================
# Evidence Store  (JWT required)
# =========================================================================

@app.post(
    "/api/v1/evidence/investigations/{investigation_id}/upload",
    response_model=EvidenceOut,
    tags=["Evidence Store"],
)
async def upload_evidence(
    investigation_id: uuid.UUID,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    user: User = _auth,
):
    investigation = await db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    data = await file.read()
    object_key = f"{investigation_id}/{uuid.uuid4()}_{file.filename}"
    upload_result = evidence_store.upload_evidence(object_key, data, file.content_type)

    record = EvidenceRecord(
        investigation_id=investigation_id,
        object_key=upload_result["object_key"],
        sha256_hash=upload_result["sha256"],
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)

    # In production, move this to a background task/queue rather than inline
    anchor_result = blockchain_client.anchor_hash(record.sha256_hash, str(investigation.case_id))
    record.blockchain_status = anchor_result.get("status", "not_anchored")
    await db.commit()
    await db.refresh(record)

    return record


@app.get("/api/v1/evidence/{evidence_id}/url", tags=["Evidence Store"])
async def get_evidence_download_url(evidence_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: User = _auth):
    record = await db.get(EvidenceRecord, evidence_id)
    if not record:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return {"url": evidence_store.get_evidence_url(record.object_key)}


# =========================================================================
# Alerting  (JWT required)
# =========================================================================

@app.post("/api/v1/alerts", response_model=AlertOut, tags=["Alerting"])
async def create_alert(payload: AlertCreate, db: AsyncSession = Depends(get_db), user: User = _auth):
    alert = Alert(**payload.model_dump())
    db.add(alert)
    await db.commit()
    await db.refresh(alert)

    if alert.severity in ("high", "critical"):
        await siem_client.forward_alert(alert)
        alert.sent_to_siem = True
        await db.commit()
        await db.refresh(alert)

    return alert


@app.get("/api/v1/alerts", response_model=list[AlertOut], tags=["Alerting"])
async def list_alerts(db: AsyncSession = Depends(get_db), user: User = _auth):
    result = await db.execute(select(Alert).order_by(Alert.created_at.desc()))
    return result.scalars().all()


# =========================================================================
# Reporting  (JWT required)
# =========================================================================

@app.get("/api/v1/reports/cases/{case_id}", tags=["Reporting"])
async def generate_case_report(case_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: User = _auth):
    case = await db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    investigations = (
        (await db.execute(select(Investigation).where(Investigation.case_id == case_id))).scalars().all()
    )

    investigation_blocks = []
    for inv in investigations:
        evidence = (
            (await db.execute(select(EvidenceRecord).where(EvidenceRecord.investigation_id == inv.id)))
            .scalars()
            .all()
        )
        investigation_blocks.append(
            {
                "investigation_id": inv.id,
                "query": inv.query,
                "findings_summary": inv.findings_summary,
                "evidence_count": len(evidence),
                "evidence": [
                    {"id": e.id, "sha256": e.sha256_hash, "blockchain_status": e.blockchain_status}
                    for e in evidence
                ],
            }
        )

    alerts = (await db.execute(select(Alert).where(Alert.case_id == case_id))).scalars().all()

    return {
        "case": {"id": case.id, "title": case.title, "status": case.status, "created_at": case.created_at},
        "investigations": investigation_blocks,
        "alerts": [{"id": a.id, "severity": a.severity, "title": a.title} for a in alerts],
    }


# =========================================================================
# SIEM Integration  (JWT required, except the inbound webhook)
# =========================================================================

@app.post("/api/v1/siem/forward/{alert_id}", tags=["SIEM Integration"])
async def forward_alert_to_siem(alert_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: User = _auth):
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    result = await siem_client.forward_alert(alert)
    if result.get("status") == "forwarded":
        alert.sent_to_siem = True
        await db.commit()
    return result


@app.post("/api/v1/siem/webhook", tags=["SIEM Integration"])
async def receive_siem_event(request: Request):
    """Inbound endpoint for SIEM-originated events. Intentionally open — the SIEM calls this, not a user."""
    payload = await request.json()
    # TODO: validate payload schema and route into Investigator / Alerting as needed
    return {"status": "received", "payload_keys": list(payload.keys())}


# =========================================================================
# Blockchain / Chain of Custody  (JWT required)
# =========================================================================

@app.post("/api/v1/blockchain/anchor/{evidence_id}", tags=["Blockchain / Chain of Custody"])
async def anchor_evidence(evidence_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: User = _auth):
    record = await db.get(EvidenceRecord, evidence_id)
    if not record:
        raise HTTPException(status_code=404, detail="Evidence not found")

    investigation = await db.get(Investigation, record.investigation_id)
    result = blockchain_client.anchor_hash(record.sha256_hash, str(investigation.case_id))
    record.blockchain_status = result.get("status", record.blockchain_status)
    await db.commit()
    return result


@app.get("/api/v1/blockchain/verify/{evidence_id}", tags=["Blockchain / Chain of Custody"])
async def verify_evidence(evidence_id: uuid.UUID, db: AsyncSession = Depends(get_db), user: User = _auth):
    record = await db.get(EvidenceRecord, evidence_id)
    if not record:
        raise HTTPException(status_code=404, detail="Evidence not found")

    investigation = await db.get(Investigation, record.investigation_id)
    return blockchain_client.verify_anchor(record.sha256_hash, str(investigation.case_id))


# =========================================================================
# Dashboard  (JWT required)
# =========================================================================

@app.get("/api/v1/dashboard/summary", tags=["Dashboard"])
async def get_dashboard_summary(db: AsyncSession = Depends(get_db), user: User = _auth):
    total_cases = (await db.execute(select(func.count()).select_from(Case))).scalar_one()
    open_cases = (
        await db.execute(select(func.count()).select_from(Case).where(Case.status == "open"))
    ).scalar_one()

    alert_counts_by_severity = (
        await db.execute(select(Alert.severity, func.count()).group_by(Alert.severity))
    ).all()

    return {
        "total_cases": total_cases,
        "open_cases": open_cases,
        "alerts_by_severity": {severity: count for severity, count in alert_counts_by_severity},
    }


# =========================================================================
# Ingestion — Module 2 (crawler) feeds data in here.
# Protected by a shared API key, not user JWT — this is service-to-service.
# =========================================================================

@app.post("/api/v1/ingestion/document", tags=["Ingestion (Module 2)"])
async def ingest_document(payload: DocumentIngest, _=Depends(verify_ingestion_key)):
    document = payload.model_dump(exclude={"entity", "doc_id"})
    result = await elasticsearch_client.index_document(payload.entity, payload.doc_id, document)
    return {"status": "indexed", "entity": payload.entity, "doc_id": payload.doc_id, "es_result": result.get("result")}


@app.post("/api/v1/ingestion/document/batch", tags=["Ingestion (Module 2)"])
async def ingest_documents_batch(payloads: list[DocumentIngest], _=Depends(verify_ingestion_key)):
    results = []
    for payload in payloads:
        document = payload.model_dump(exclude={"entity", "doc_id"})
        result = await elasticsearch_client.index_document(payload.entity, payload.doc_id, document)
        results.append({"doc_id": payload.doc_id, "status": result.get("result")})
    return {"ingested": len(results), "results": results}


@app.post("/api/v1/ingestion/entity", tags=["Ingestion (Module 2)"])
async def ingest_entity(payload: EntityIngest, _=Depends(verify_ingestion_key)):
    result = await neo4j_client.upsert_entity(payload.label, payload.id, payload.properties)
    return {"status": "upserted", "label": payload.label, "id": payload.id, "result": result}


@app.post("/api/v1/ingestion/relationship", tags=["Ingestion (Module 2)"])
async def ingest_relationship(payload: RelationshipIngest, _=Depends(verify_ingestion_key)):
    result = await neo4j_client.link_entities(payload.source_id, payload.target_id, payload.relationship)
    return {"status": "linked", "result": result}
