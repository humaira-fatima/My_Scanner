import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import logging
import asyncio
from fastapi import FastAPI, Depends, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel

from database import SessionLocal, engine
import models
from models import TargetDomain, Asset, Finding, BountyProfile
from schemas import TargetSessionUpdate, BountyProfileCreate, BountyProfileResponse
from recon import ReconEngine
from http_client import SecureScannerClient

from active_scanner import run_full_scan_pipeline
from owasp_logic_engine import BusinessLogicEngine

# Standalone scanner engine imports
from js_miner import mine_multiple_js_assets
from dom_scanner import run_dom_scan

models.Base.metadata.create_all(bind=engine)

logger = logging.getLogger("FastAPI_Engine")

app = FastAPI(
    title="My_Scanner Security Recon Engine",
    version="2.0.0",
    description="Single-tenant automated security reconnaissance and HackerOne report management backend."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def build_base_url(domain_name: str) -> str:
    """Helper to dynamically format target URL scheme."""
    if domain_name.startswith("http://") or domain_name.startswith("https://"):
        return domain_name.rstrip("/")
    if "127.0.0.1" in domain_name or "localhost" in domain_name:
        return f"http://{domain_name}".rstrip("/")
    return f"https://{domain_name}".rstrip("/")

class TargetCreate(BaseModel):
    domain_name: str
    platform: Optional[str] = "HackerOne"

class ScanTriggerRequest(BaseModel):
    target_id: int

# =====================================================================
# SYSTEM & TARGET MANAGEMENT ROUTES
# =====================================================================

@app.get("/")
def read_root():
    return {"status": "online", "system": "My_Scanner Recon Engine Pipeline Active"}

@app.get("/api/targets", response_model=List[dict])
def get_targets(db: Session = Depends(get_db)):
    targets = db.query(TargetDomain).all()
    return [{"id": t.id, "domain_name": t.domain_name, "platform": getattr(t, "platform", "HackerOne")} for t in targets]

@app.post("/api/targets", status_code=201)
def add_target(payload: TargetCreate, db: Session = Depends(get_db)):
    existing = db.query(TargetDomain).filter(TargetDomain.domain_name == payload.domain_name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Target domain already exists.")
    
    new_target = TargetDomain(domain_name=payload.domain_name, platform=payload.platform)
    db.add(new_target)
    db.commit()
    db.refresh(new_target)
    logger.info(f"Added new target domain: {new_target.domain_name} [{new_target.platform}]")
    return {"message": "Target added successfully", "id": new_target.id, "domain_name": new_target.domain_name, "platform": new_target.platform}

@app.delete("/api/targets/{target_id}")
def delete_target(target_id: int, db: Session = Depends(get_db)):
    target = db.query(TargetDomain).filter(TargetDomain.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target domain not found")
        
    db.query(Finding).filter(Finding.target_id == target_id).delete()
    db.query(Asset).filter(Asset.target_id == target_id).delete()
    db.delete(target)
    db.commit()
    
    logger.info(f"Deleted target ID {target_id} ({target.domain_name}) and associated records.")
    return {"message": f"Target {target.domain_name} and associated findings deleted successfully."}

@app.delete("/api/targets/{target_id}/findings")
def clear_target_findings(target_id: int, db: Session = Depends(get_db)):
    deleted_count = db.query(Finding).filter(Finding.target_id == target_id).delete()
    db.commit()
    logger.info(f"Cleared {deleted_count} findings for target ID {target_id}.")
    return {"message": f"Cleared {deleted_count} findings successfully."}

# =====================================================================
# BACKGROUND TASK HANDLERS
# =====================================================================

def background_recon_task(target_id: int, scan_type: str = "Passive Recon"):
    db = SessionLocal()
    try:
        target = db.query(TargetDomain).filter(TargetDomain.id == target_id).first()
        if not target:
            logger.error(f"Background recon failed: Target ID {target_id} not found.")
            return
        
        base_url = build_base_url(target.domain_name)
        logger.info(f"[*] Starting background {scan_type} pipeline for target: {base_url}")
        
        client = SecureScannerClient(db)
        engine = ReconEngine(db, client)
        
        engine.discover_subdomains(target.domain_name)
        engine.discover_js_endpoints(target.domain_name)
        engine.monitor_js_changes(target.domain_name)
        
        logger.info(f"[*] {scan_type} pipeline completed successfully for {target.domain_name}")
        
    except Exception as e:
        logger.error(f"Error executing background recon task: {e}")
    finally:
        db.close()

async def background_js_miner_task(target_id: int):
    db = SessionLocal()
    try:
        target = db.query(TargetDomain).filter(TargetDomain.id == target_id).first()
        if not target:
            return

        # Fetch all discovered JS bundle URLs for this target from the database
        js_assets = db.query(Asset).filter(
            Asset.target_id == target_id,
            Asset.asset_type == "js_bundle"
        ).all()
        
        js_urls = [a.value for a in js_assets]

        # Fallback to standard bundle URLs if none are found in the DB yet
        if not js_urls:
            base_url = build_base_url(target.domain_name)
            js_urls = [f"{base_url}/main.js", f"{base_url}/app.js", f"{base_url}/static/js/main.js"]

        # Run your async mining pipeline
        logger.info(f"[*] Starting JS Miner pipeline for target ID {target_id}")
        await mine_multiple_js_assets(db, target.id, js_urls)

    except Exception as e:
        logger.error(f"JS Miner error: {e}")
    finally:
        db.close()

async def background_dom_scanner_task(target_id: int):
    db = SessionLocal()
    try:
        target = db.query(TargetDomain).filter(TargetDomain.id == target_id).first()
        if target:
            target_url = build_base_url(target.domain_name)
            logger.info(f"[*] Starting DOM Scanner pipeline for target: {target.domain_name}")
            await run_dom_scan(db, target.id, target_url)
            logger.info(f"[*] DOM Scanner task completed for {target.domain_name}")
    except Exception as e:
        logger.error(f"DOM Scanner error: {e}")
    finally:
        db.close()

async def background_active_scan_task(target_id: int):
    db = SessionLocal()
    try:
        target = db.query(TargetDomain).filter(TargetDomain.id == target_id).first()
        if not target:
            logger.error(f"Active scan failed: Target ID {target_id} not found.")
            return

        target_url = build_base_url(target.domain_name)
        logger.info(f"[*] Starting full active scan pipeline for: {target_url}")

        scan_results = await run_full_scan_pipeline(
            db=db,
            target_id=target.id,
            target_url=target_url,
            skip_nuclei=False,
            concurrency=10,
            export_json_path=None,
            export_html_path=None
        )
        raw_findings = scan_results.get("nuclei_findings", []) if scan_results else []

        for raw in raw_findings:
            info = raw.get("info", {})
            title = info.get("name", "Unnamed Vulnerability")
            severity = info.get("severity", "info").lower()
            endpoint = raw.get("matched-at", target_url)
            description = info.get("description", "No description provided.")

            existing = db.query(Finding).filter(
                Finding.target_id == target.id,
                Finding.title == title,
                Finding.endpoint == endpoint
            ).first()

            if not existing:
                new_finding = Finding(
                    target_id=target.id,
                    title=title,
                    severity=severity,
                    endpoint=endpoint,
                    draft_report=description,
                    is_verified=True
                )
                db.add(new_finding)
                db.commit()

        logger.info(f"[*] Active scan completed successfully for {target.domain_name}")

    except Exception as e:
        logger.error(f"Error executing background active scan task: {e}")
    finally:
        db.close()

def background_logic_task(target_id: int, scan_type: str = "OWASP Logic"):
    db = SessionLocal()
    try:
        target = db.query(TargetDomain).filter(TargetDomain.id == target_id).first()
        if not target:
            logger.error(f"Logic task failed: Target ID {target_id} not found.")
            return

        logger.info(f"[*] Starting {scan_type} testing for target: {target.domain_name}")

        try:
            logic_engine = BusinessLogicEngine(db, target)
            scan_results = logic_engine.run_all_checks(scan_type) 

            if not scan_results:
                logger.info(f"No {scan_type} vulnerabilities found.")
                return 

            for finding in scan_results:
                existing = db.query(Finding).filter(
                    Finding.target_id == target.id, 
                    Finding.title == finding['title'],
                    Finding.endpoint == finding['endpoint']
                ).first()
                
                if not existing:
                    new_finding = Finding(
                        target_id=target.id,
                        title=finding['title'],
                        severity=finding['severity'],
                        endpoint=finding['endpoint'],
                        draft_report=finding['report_body'],
                        is_verified=True
                    )
                    db.add(new_finding)
            db.commit()

        except Exception as e:
            logger.error(f"Engine checks completed with notice or error: {e}")

        logger.info(f"[*] {scan_type} pipeline completed successfully for {target.domain_name}")

    except Exception as e:
        logger.error(f"Error executing logic task: {e}")
    finally:
        db.close()

# =====================================================================
# API SCAN TRIGGER ENDPOINTS
# =====================================================================

@app.post("/api/scan/trigger")
def trigger_scan(payload: ScanTriggerRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    target = db.query(TargetDomain).filter(TargetDomain.id == payload.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target domain not found.")
    background_tasks.add_task(background_recon_task, target.id, "Passive Recon")
    return {"message": f"Recon pipeline successfully queued for target ID {target.id} ({target.domain_name})."}

@app.post("/api/scan/active")
def trigger_active_scan(payload: ScanTriggerRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    target = db.query(TargetDomain).filter(TargetDomain.id == payload.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target domain not found.")
    background_tasks.add_task(background_active_scan_task, target.id)
    return {"message": f"Active scanning pipeline successfully queued for target ID {target.id} ({target.domain_name})."}

@app.post("/api/scan/owasp/logic")
def trigger_logic_scan(payload: ScanTriggerRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    target = db.query(TargetDomain).filter(TargetDomain.id == payload.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target domain not found.")

    if not getattr(target, "auth_token_a", None):
        raise HTTPException(
            status_code=400, 
            detail="User session tokens required for logic testing. Please configure in Manage Sessions."
        )

    background_tasks.add_task(background_logic_task, target.id, "OWASP Logic")
    return {"message": f"OWASP Logic pipeline successfully queued for target ID {target.id} ({target.domain_name})."}

@app.post("/api/scan/js_miner")
def trigger_js_miner(payload: ScanTriggerRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    target = db.query(TargetDomain).filter(TargetDomain.id == payload.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target domain not found.")
    background_tasks.add_task(background_js_miner_task, target.id)
    return {"message": f"JS Miner pipeline queued for {target.domain_name}."}

@app.post("/api/scan/dom_scanner")
def trigger_dom_scanner(payload: ScanTriggerRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    target = db.query(TargetDomain).filter(TargetDomain.id == payload.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target domain not found.")
    background_tasks.add_task(background_dom_scanner_task, target.id)
    return {"message": f"DOM Scanner pipeline queued for {target.domain_name}."}

@app.post("/api/scan/xss")
def trigger_xss_scan(payload: ScanTriggerRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    target = db.query(TargetDomain).filter(TargetDomain.id == payload.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target domain not found.")
    background_tasks.add_task(background_active_scan_task, target.id)
    return {"message": f"Active XSS scan pipeline queued for {target.domain_name}."}

@app.post("/api/scan/xxe")
def trigger_xxe_scan(payload: ScanTriggerRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    target = db.query(TargetDomain).filter(TargetDomain.id == payload.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target domain not found.")
    background_tasks.add_task(background_active_scan_task, target.id)
    return {"message": f"XXE / XML engine pipeline queued for {target.domain_name}."}

@app.post("/api/scan/bola")
def trigger_bola_engine(payload: ScanTriggerRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    target = db.query(TargetDomain).filter(TargetDomain.id == payload.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target domain not found.")

    if not getattr(target, "auth_token_a", None) or not getattr(target, "auth_token_b", None):
        raise HTTPException(
            status_code=400, 
            detail="Both User A and User B session tokens are required for BOLA testing. Configure in Manage Sessions."
        )

    background_tasks.add_task(background_logic_task, target.id, "BOLA Engine")
    return {"message": f"BOLA Engine pipeline queued for {target.domain_name}."}

# =====================================================================
# DATA & SESSION MANAGEMENT ENDPOINTS
# =====================================================================

@app.post("/api/targets/{target_id}/sessions")
def update_target_sessions(target_id: int, payload: TargetSessionUpdate, db: Session = Depends(get_db)):
    target = db.query(TargetDomain).filter(TargetDomain.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target domain not found.")
    
    target.auth_token_a = payload.auth_token_a
    target.auth_token_b = payload.auth_token_b
    db.commit()
    
    logger.info(f"Updated session tokens for target ID {target.id}")
    return {"message": "Session tokens saved securely."}

@app.get("/api/assets", response_model=List[dict])
def get_assets(db: Session = Depends(get_db)):
    assets = db.query(Asset).all()
    return [
        {
            "id": a.id,
            "target_id": a.target_id,
            "asset_type": a.asset_type,
            "value": a.value,
            "content_hash": a.content_hash
        }
        for a in assets
    ]

@app.get("/api/findings", response_model=List[dict])
def get_findings(db: Session = Depends(get_db)):
    findings = db.query(Finding).all()
    return [
        {
            "id": f.id,
            "target_id": f.target_id,
            "title": f.title,
            "severity": f.severity,
            "endpoint": f.endpoint,
            "draft_report": f.draft_report,
            "is_verified": f.is_verified,
        }
        for f in findings
    ]

@app.post("/api/profiles", response_model=BountyProfileResponse, status_code=201)
def add_bounty_profile(payload: BountyProfileCreate, db: Session = Depends(get_db)):
    new_profile = BountyProfile(
        platform_name=payload.platform_name,
        api_key=payload.api_key,
        username=payload.username
    )
    db.add(new_profile)
    db.commit()
    db.refresh(new_profile)
    return new_profile