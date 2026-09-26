import httpx
import time
import logging
import uuid
from urllib.parse import urlparse
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from models import BountyProfile, TargetDomain

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ScopeGuard")

class SecureScannerClient:
    """
    CORE HTTP ENGINE & SCOPE GUARD
    Wraps httpx to enforce rate limits, identity headers, domain whitelisting,
    and soft-404 detection across all vulnerability modules.
    """
    def __init__(self, db: Session):
        self.db = db
        self.active_profile = self._get_active_profile()
        self.rate_limit_delay = 0.2  # 5 Requests Per Second (RPS) cap
        
        # Route and method protection
        self.blocked_routes = ["/logout", "/checkout/buy", "/admin/reset", "/delete_account"]
        self.blocked_methods = ["DELETE", "PURGE"]

    def _get_active_profile(self) -> Optional[BountyProfile]:
        """Queries the database for the active bounty profile."""
        return self.db.query(BountyProfile).filter(BountyProfile.is_active == True).first()

    def _is_in_scope(self, url: str) -> bool:
        """
        Parses the target URL host and verifies it against configured in-scope domains,
        supporting exact domain and subdomain matching.
        """
        parsed_host = urlparse(url).netloc.split(':')[0].lower()
        targets = self.db.query(TargetDomain).all()
        
        for target in targets:
            domain = target.domain_name.lower()
            if parsed_host == domain or parsed_host.endswith("." + domain):
                if getattr(target, "is_in_scope", True):
                    return True
        return False

    def execute_request(
        self, 
        method: str, 
        url: str, 
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        follow_redirects: bool = True
    ) -> Optional[httpx.Response]:
        """
        Executes HTTP requests with identity injection, rate limiting, and 
        scope enforcement. Returns full httpx.Response for status code analysis.
        """
        # 1. Scope & Blacklist Guards
        if not self._is_in_scope(url):
            logger.warning(f"BLOCKED: {url} is out of scope.")
            return None
            
        if method.upper() in self.blocked_methods or any(route in url for route in self.blocked_routes):
            logger.warning(f"BLOCKED: Destructive method or route detected -> {method} {url}")
            return None

        # 2. Identity Header Construction
        req_headers = {
            "User-Agent": getattr(self.active_profile, "user_agent_string", "My_Scanner_Security_Engine/2.0"),
            "X-Research-Email": getattr(self.active_profile, "email_alias", "researcher@bugbounty.local")
        }

        if self.active_profile and getattr(self.active_profile, "custom_header_key", None):
            req_headers[self.active_profile.custom_header_key] = self.active_profile.username

        # Inject additional request-specific headers (e.g. auth tokens)
        if headers:
            req_headers.update(headers)

        # 3. Rate Limiting Execution Cap
        time.sleep(self.rate_limit_delay)
        
        try:
            with httpx.Client(
                headers=req_headers, 
                cookies=cookies, 
                timeout=12.0, 
                verify=False,
                follow_redirects=follow_redirects
            ) as client:
                logger.info(f"SCANNING: {method.upper()} {url}")
                # Note: raise_for_status() is omitted to allow status code inspection (401, 403, 404)
                response = client.request(
                    method=method.upper(), 
                    url=url, 
                    params=params, 
                    data=data, 
                    json=json
                )
                return response
                
        except httpx.TimeoutException:
            logger.error(f"TIMEOUT: Target {url} failed to respond within 12 seconds.")
        except httpx.HTTPError as exc:
            logger.error(f"HTTP ERROR: {exc} while requesting {url}")
            
        return None

    def check_soft_404(self, base_url: str) -> Dict[str, Any]:
        """
        Sends a request to a random non-existent path to establish a baseline status, 
        body length, and response pattern for detecting dynamic soft-404 pages.
        """
        parsed = urlparse(base_url)
        random_path = f"{parsed.scheme}://{parsed.netloc}/non_existent_{uuid.uuid4().hex[:8]}"
        response = self.execute_request("GET", random_path)
        
        if response:
            return {
                "status_code": response.status_code,
                "content_length": len(response.text),
                "is_soft_404": response.status_code == 200,
                "sample_text": response.text[:200]
            }
        return {"status_code": 404, "content_length": 0, "is_soft_404": False, "sample_text": ""}