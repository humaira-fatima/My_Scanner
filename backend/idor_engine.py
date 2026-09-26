import logging
import httpx
from typing import Dict, Any
from sqlalchemy.orm import Session
from models import BountyProfile, Finding

logger = logging.getLogger("IDOREngine")

def contains_generic_error(response_text: str) -> bool:
    """
    Safely checks if a response body contains a generic error without triggering
    false negatives on large data payloads that happen to contain words like 'error'.
    """
    text_lower = response_text.lower().strip()
    if text_lower in ["{}", "[]", "null", ""]:
        return True
    
    # If response is large (> 300 chars), treat as real data to avoid false negatives
    if len(text_lower) > 300:
        return False
        
    return any(indicator in text_lower for indicator in ["\"error\":", "\"message\":", "access denied", "unauthorized", "not found"])


async def run_bola_scan(db: Session, target_id: int, endpoint_url: str, resource_id: str) -> Dict[str, Any]:
    """
    Executes a multi-account BOLA/IDOR authorization check.
    Differentiates between BOLA vulnerabilities, public endpoints, and soft-404 error responses.
    """
    profiles = db.query(BountyProfile).filter(
        BountyProfile.is_active == True
    ).limit(2).all()

    if len(profiles) < 2:
        logger.warning("BOLA test aborted: Requires at least 2 active BountyProfiles in DB.")
        return {"status": "error", "message": "Need 2 active accounts to test BOLA/IDOR."}

    account_a, account_b = profiles[0], profiles[1]

    headers_a = {
        "User-Agent": getattr(account_a, "user_agent_string", "My_Scanner_Engine"),
        "X-Research-Email": getattr(account_a, "email_alias", "researcher@bugbounty.local")
    }
    headers_b = {
        "User-Agent": getattr(account_b, "user_agent_string", "My_Scanner_Engine"),
        "X-Research-Email": getattr(account_b, "email_alias", "researcher@bugbounty.local")
    }

    if getattr(account_a, "custom_header_key", None):
        headers_a[account_a.custom_header_key] = account_a.username
    if getattr(account_b, "custom_header_key", None):
        headers_b[account_b.custom_header_key] = account_b.username

    test_url = endpoint_url.replace("{ID}", str(resource_id))

    async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=True) as client:
        try:
            # Step 1: Baseline request by Account A (Owner)
            res_a = await client.get(test_url, headers=headers_a)
            if res_a.status_code != 200 or contains_generic_error(res_a.text):
                logger.info(f"BOLA skipped: Resource URL {test_url} returned invalid status or error for owner.")
                return {"status": "skipped", "reason": "Resource not accessible by Account A"}

            # Step 2: Unauthenticated check (Determines if endpoint is intentionally public)
            res_unauth = await client.get(test_url, headers={"User-Agent": "My_Scanner_Engine"})
            if res_unauth.status_code == 200 and not contains_generic_error(res_unauth.text):
                if abs(len(res_unauth.text) - len(res_a.text)) < 30:
                    logger.info(f"BOLA skipped: {test_url} is a public endpoint.")
                    return {"status": "public_endpoint", "endpoint": test_url}

            # Step 3: Cross-Account Check (Account B attempts to access Account A's resource)
            res_b = await client.get(test_url, headers=headers_b)

            # Step 4: Verification Logic to prevent False Positives
            is_status_200 = res_b.status_code == 200
            is_not_error = not contains_generic_error(res_b.text)

            if is_status_200 and is_not_error:
                logger.warning(f"[!] BOLA/IDOR Confirmed: {account_b.username} accessed {test_url}")

                existing = db.query(Finding).filter(
                    Finding.target_id == target_id,
                    Finding.title == "BOLA / IDOR Vulnerability Detected",
                    Finding.endpoint == test_url
                ).first()

                if not existing:
                    finding = Finding(
                        target_id=target_id,
                        title="BOLA / IDOR Vulnerability Detected",
                        severity="High",
                        endpoint=test_url,
                        details_json=(
                            f"Account B ({account_b.username}) successfully retrieved "
                            f"private resource owned by Account A ({account_a.username}). "
                            f"Response status: 200 OK. Body length: {len(res_b.text)} bytes."
                        ),
                        is_verified=True
                    )
                    db.add(finding)
                    db.commit()

                return {"status": "vulnerable", "endpoint": test_url}

        except Exception as e:
            logger.error(f"BOLA check execution failed for {test_url}: {e}")
            return {"status": "error", "message": str(e)}

    return {"status": "secure", "endpoint": test_url}