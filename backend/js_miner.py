import re
import hashlib
import logging
import httpx
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from models import Asset, Finding

logger = logging.getLogger("JSMiner")

# Patterns for extracting endpoints and routes from minified JS
ENDPOINT_PATTERN = re.compile(
    r'(?:"|\')(((?:[a-zA-Z]{1,10}://|/)[^"\'\s]+|([a-zA-Z0-9_\-]+/)+[a-zA-Z0-9_\-]+))(?:"|\')'
)

# ID Normalization Patterns (Converts Numbers & UUIDs to BOLA {ID} placeholders)
NUMERIC_ID_PATTERN = re.compile(r'/(\d+)(?=/|$|\?)')
UUID_PATTERN = re.compile(
    r'/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', 
    re.IGNORECASE
)

# Common static file extensions that do not contain API routes
IGNORED_EXTENSIONS = (
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.woff', '.woff2', 
    '.ttf', '.ico', '.eot', '.otf', '.map', '.mp4', '.mp3', '.webm', 
    '.pdf', '.zip', '.gz', '.js'
)

# Strings, MIME types, and code keywords commonly misidentified as endpoints
EXCLUDE_STRINGS = {
    "text/html", "text/plain", "text/css", "text/javascript",
    "application/json", "application/x-www-form-urlencoded",
    "multipart/form-data", "application/xml", "use strict",
    "utf-8", "utf8", "GET", "POST", "PUT", "DELETE", "PATCH"
}


def normalize_endpoint(endpoint: str) -> str:
    """Converts numeric path IDs and UUIDs to BOLA placeholders (/api/users/{ID})."""
    ep = NUMERIC_ID_PATTERN.sub(r'/{ID}', endpoint)
    return UUID_PATTERN.sub(r'/{ID}', ep)


def is_valid_endpoint(endpoint: str) -> bool:
    """Filters out non-route strings, MIME types, and static resources to prevent false positives."""
    if not endpoint or len(endpoint) < 2 or len(endpoint) > 200:
        return False
    
    ep_lower = endpoint.lower().strip()
    
    if ep_lower in EXCLUDE_STRINGS or ep_lower.startswith("http://www.w3.org"):
        return False
        
    if ep_lower.endswith(IGNORED_EXTENSIONS):
        return False

    # Exclude JS comment patterns or internal syntax glitches
    if "//" in endpoint and not (endpoint.startswith("http://") or endpoint.startswith("https://")):
        return False

    return True


async def analyze_js_asset(db: Session, target_id: int, js_url: str) -> Dict[str, Any]:
    """
    Downloads a JS file, tracks content updates via MD5 hashing, 
    extracts API endpoints, and populates the Asset table.
    """
    discovered_endpoints: List[str] = []
    
    async with httpx.AsyncClient(timeout=12.0, follow_redirects=True, verify=False) as client:
        try:
            response = await client.get(js_url)
            if response.status_code != 200:
                logger.warning(f"Failed to fetch JS asset {js_url}: Status {response.status_code}")
                return {"js_url": js_url, "status": "failed", "endpoints_found": 0}
            
            content = response.text
        except Exception as e:
            logger.error(f"Error requesting JS asset {js_url}: {e}")
            return {"js_url": js_url, "status": "error", "endpoints_found": 0}

    # 1. MD5 content hash calculation for change detection
    new_hash = hashlib.md5(content.encode('utf-8')).hexdigest()
    
    # 2. JS Change Detection / Diffing
    js_asset = db.query(Asset).filter(
        Asset.target_id == target_id,
        Asset.value == js_url,
        Asset.asset_type == "js_bundle"
    ).first()

    if js_asset:
        if js_asset.content_hash != new_hash:
            logger.info(f"[!] JS Asset change detected for: {js_url}")
            change_finding = Finding(
                target_id=target_id,
                title=f"JS Bundle Updated: {js_url.split('/')[-1]}",
                severity="info",
                endpoint=js_url,
                draft_report=f"JavaScript bundle hash changed from `{js_asset.content_hash}` to `{new_hash}`. Review newly extracted endpoints.",
                is_verified=True
            )
            db.add(change_finding)
            js_asset.content_hash = new_hash
    else:
        new_js_asset = Asset(
            target_id=target_id,
            asset_type="js_bundle",
            value=js_url,
            content_hash=new_hash
        )
        db.add(new_js_asset)

    # 3. Extract and Validate Endpoints
    matches = ENDPOINT_PATTERN.findall(content)
    
    for match in matches:
        raw_url = match[0]
        
        if is_valid_endpoint(raw_url):
            if raw_url.startswith("/") or "/api/" in raw_url or "v1/" in raw_url or "v2/" in raw_url:
                normalized_url = normalize_endpoint(raw_url)
                discovered_endpoints.append(normalized_url)

    # 4. Deduplicate and Store Assets
    unique_endpoints = list(set(discovered_endpoints))
    added_count = 0

    for ep in unique_endpoints:
        existing = db.query(Asset).filter(
            Asset.target_id == target_id,
            Asset.value == ep,
            Asset.asset_type == "endpoint"
        ).first()

        if not existing:
            endpoint_asset = Asset(
                target_id=target_id,
                asset_type="endpoint",
                value=ep,
                content_hash=None
            )
            db.add(endpoint_asset)
            added_count += 1

    db.commit()
    logger.info(f"[+] Mined {js_url}: Found {len(unique_endpoints)} valid endpoints ({added_count} new saved).")
    
    return {
        "js_url": js_url,
        "status": "success",
        "endpoints_found": len(unique_endpoints),
        "new_endpoints_saved": added_count
    }


async def mine_multiple_js_assets(db: Session, target_id: int, js_urls: List[str]) -> List[Dict[str, Any]]:
    """Runs JS mining across multiple JS bundle URLs."""
    results = []
    for url in js_urls:
        res = await analyze_js_asset(db, target_id, url)
        results.append(res)
    return results