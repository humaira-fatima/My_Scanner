import logging
import httpx
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from models import TargetDomain, Finding

logger = logging.getLogger("FastAPI_Engine")

ERROR_INDICATORS = [
    "unauthorized", "access denied", "forbidden", "permission denied",
    "not found", "login required", "authentication required", "invalid token"
]

def contains_generic_error(response_text: str) -> bool:
    """Safely checks if a response body contains a generic error or empty JSON payload."""
    text_lower = response_text.lower().strip()
    if text_lower in ["{}", "[]", "null", ""]:
        return True
    if len(text_lower) > 300:
        return False
    return any(indicator in text_lower for indicator in ERROR_INDICATORS)

def build_target_url(domain_name: str) -> str:
    """Dynamically resolves HTTP/HTTPS schemes based on target host."""
    if domain_name.startswith("http://") or domain_name.startswith("https://"):
        return domain_name.rstrip("/")
    if "127.0.0.1" in domain_name or "localhost" in domain_name:
        return f"http://{domain_name}".rstrip("/")
    return f"https://{domain_name}".rstrip("/")


class BusinessLogicEngine:
    """
    OWASP BUSINESS LOGIC & AUTHORIZATION ENGINE
    Tests endpoints for BOLA/IDOR, Mass Assignment, Workflow Bypasses, and Header Injection.
    """
    def __init__(self, db: Session, target: TargetDomain):
        self.db = db
        self.target = target
        self.base_url = build_target_url(target.domain_name)
        
        self.token_a = getattr(target, "auth_token_a", None)
        self.token_b = getattr(target, "auth_token_b", None)

        self.headers_user_a = {
            "Authorization": f"Bearer {self.token_a}" if self.token_a else "",
            "Content-Type": "application/json",
            "User-Agent": "My_Scanner_Logic_Engine/2.0"
        }
        self.headers_user_b = {
            "Authorization": f"Bearer {self.token_b}" if self.token_b else "",
            "Content-Type": "application/json",
            "User-Agent": "My_Scanner_Logic_Engine/2.0"
        }

    def _save_finding(self, title: str, severity: str, endpoint: str, description: str) -> Optional[Dict[str, Any]]:
        """Helper method to deduplicate and save findings into the database."""
        existing = self.db.query(Finding).filter(
            Finding.target_id == self.target.id,
            Finding.title == title,
            Finding.endpoint == endpoint
        ).first()

        finding_dict = {
            "title": title,
            "severity": severity,
            "endpoint": endpoint,
            "report_body": description
        }

        if not existing:
            new_finding = Finding(
                target_id=self.target.id,
                title=title,
                severity=severity,
                endpoint=endpoint,
                draft_report=description,
                is_verified=True
            )
            self.db.add(new_finding)
            self.db.commit()
            logger.info(f"[+] Verified Logic Vulnerability Logged: {title} on {endpoint}")

        return finding_dict

    def test_bola(self) -> List[Dict[str, Any]]:
        """
        A01: Broken Object Level Authorization (BOLA / IDOR)
        Validates cross-account object access by requesting User A resources using User B tokens.
        """
        logger.info(f"[*] Executing BOLA Authorization tests on {self.base_url}")
        results = []

        if not self.token_a or not self.token_b:
            logger.warning("[-] BOLA testing skipped: Both User A and User B session tokens are required.")
            return results

        target_resource_endpoints = [
            "/api/v1/users/1",
            "/api/v1/user/1",
            "/api/v1/users/profile/1",
            "/api/v1/orders/1",
            "/api/v1/account/1",
            "/api/users/1"
        ]

        with httpx.Client(timeout=10.0, verify=False, follow_redirects=True) as client:
            for ep in target_resource_endpoints:
                url = f"{self.base_url}{ep}"
                
                try:
                    # Step 1: Query object as User A (Baseline Access Verification)
                    res_a = client.get(url, headers=self.headers_user_a)
                    if res_a.status_code != 200 or contains_generic_error(res_a.text):
                        continue

                    # Step 2: Query identical object as User B (Cross-Account Access Verification)
                    res_b = client.get(url, headers=self.headers_user_b)

                    # Step 3: Determine if User B bypassed access control
                    if res_b.status_code == 200 and not contains_generic_error(res_b.text):
                        finding = self._save_finding(
                            title="Broken Object Level Authorization (BOLA / IDOR)",
                            severity="high",
                            endpoint=url,
                            description=(
                                f"User B successfully retrieved private resources owned by User A at target endpoint.\n\n"
                                f"Target URL: {url}\n"
                                f"User A HTTP Response Status: {res_a.status_code}\n"
                                f"User B HTTP Response Status: {res_b.status_code}\n"
                                f"Response Preview (User B Context):\n{res_b.text[:300]}"
                            )
                        )
                        if finding:
                            results.append(finding)

                except Exception as e:
                    logger.debug(f"BOLA check skipped for {url}: {e}")

        return results

    def test_mass_assignment(self) -> List[Dict[str, Any]]:
        """
        A01: Mass Assignment / Property Ingestion
        Tests state-changing endpoints for unauthorized permission escalation via key injection.
        """
        logger.info(f"[*] Executing Mass Assignment tests on {self.base_url}")
        results = []
        target_endpoints = ["/api/v1/user/profile", "/api/user", "/api/settings", "/api/v1/me"]
        elevated_payloads = [
            {"is_admin": True, "role": "admin"},
            {"admin": 1, "access_level": "administrator"},
            {"account_type": "superuser"}
        ]

        with httpx.Client(timeout=10.0, verify=False, follow_redirects=True) as client:
            for ep in target_endpoints:
                url = f"{self.base_url}{ep}"
                
                try:
                    base_res = client.get(url, headers=self.headers_user_a)
                    if base_res.status_code != 200 or contains_generic_error(base_res.text):
                        continue
                except Exception:
                    continue

                for payload in elevated_payloads:
                    for method in ["PUT", "PATCH"]:
                        try:
                            res = client.request(method, url, json=payload, headers=self.headers_user_a)
                            if res.status_code in [200, 201]:
                                try:
                                    res_json = res.json()
                                    if not isinstance(res_json, dict):
                                        continue
                                    
                                    elevated_matched = {
                                        k: v for k, v in payload.items() 
                                        if k in res_json and res_json[k] == v
                                    }

                                    if elevated_matched:
                                        finding = self._save_finding(
                                            title="Mass Assignment Vulnerability",
                                            severity="high",
                                            endpoint=url,
                                            description=(
                                                f"The endpoint accepted privilege escalation properties via {method} "
                                                f"and returned confirmed elevated attributes.\n\n"
                                                f"Payload sent: {payload}\n"
                                                f"Elevated properties confirmed: {elevated_matched}"
                                            )
                                        )
                                        if finding:
                                            results.append(finding)
                                        break
                                except ValueError:
                                    continue
                        except Exception as e:
                            logger.debug(f"Mass assignment test skipped for {url} ({method}): {e}")

        return results

    def test_workflow_bypass(self) -> List[Dict[str, Any]]:
        """
        A04: Workflow Bypass
        Attempts direct access to post-transaction/restricted state endpoints.
        """
        logger.info(f"[*] Executing Workflow Bypass tests on {self.base_url}")
        results = []
        restricted_stages = [
            "/api/v1/checkout/confirm",
            "/api/v1/admin/dashboard",
            "/api/v1/onboarding/complete",
            "/api/v1/payment/process"
        ]

        with httpx.Client(timeout=10.0, verify=False, follow_redirects=True) as client:
            for ep in restricted_stages:
                url = f"{self.base_url}{ep}"
                try:
                    res = client.post(url, json={"status": "complete"}, headers=self.headers_user_a)
                    if res.status_code in [200, 201] and not contains_generic_error(res.text):
                        finding = self._save_finding(
                            title="Workflow Bypass / Forced Browsing",
                            severity="high",
                            endpoint=url,
                            description=(
                                f"Direct POST request to terminal workflow endpoint returned HTTP {res.status_code} "
                                f"without enforcing prerequisite state verification tokens.\n\n"
                                f"Response preview: {res.text[:200]}"
                            )
                        )
                        if finding:
                            results.append(finding)
                except Exception as e:
                    logger.debug(f"Workflow test skipped for {url}: {e}")

        return results

    def test_blind_ssrf(self) -> List[Dict[str, Any]]:
        """
        A10: SSRF / Host Header Injection
        Tests routing header manipulations against baseline responses.
        """
        logger.info(f"[*] Executing SSRF and Header Injection checks on {self.base_url}")
        results = []
        ssrf_headers = {
            "X-Forwarded-Host": "127.0.0.1",
            "X-Host": "127.0.0.1",
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1"
        }

        with httpx.Client(timeout=10.0, verify=False, follow_redirects=False) as client:
            try:
                base_res = client.get(f"{self.base_url}/", headers=self.headers_user_a)
                
                test_headers = self.headers_user_a.copy()
                test_headers.update(ssrf_headers)
                res = client.get(f"{self.base_url}/", headers=test_headers)

                redirect_location = res.headers.get("Location", "")
                if "127.0.0.1" in redirect_location or "localhost" in redirect_location:
                    finding = self._save_finding(
                        title="Host Header Injection / SSRF Redirect Flaw",
                        severity="high",
                        endpoint=self.base_url,
                        description=(
                            f"Header injection caused server to issue a redirect pointing to an internal host address.\n\n"
                            f"Location Header: {redirect_location}"
                        )
                    )
                    if finding:
                        results.append(finding)

                elif res.status_code != base_res.status_code and res.status_code in [500, 502, 504]:
                    finding = self._save_finding(
                        title="Blind SSRF / Header Injection Routing Anomaly",
                        severity="medium",
                        endpoint=self.base_url,
                        description=(
                            f"Injecting internal routing headers altered application response state from "
                            f"HTTP {base_res.status_code} to HTTP {res.status_code}."
                        )
                    )
                    if finding:
                        results.append(finding)

            except Exception as e:
                logger.debug(f"SSRF test skipped: {e}")

        return results

    def run_all_checks(self, scan_type: str = "OWASP Logic") -> List[Dict[str, Any]]:
        """Master dispatcher executing tasks based on scan requests."""
        findings = []

        if scan_type in ["BOLA Engine", "All"]:
            findings.extend(self.test_bola())

        if scan_type in ["OWASP Logic", "All"]:
            findings.extend(self.test_mass_assignment())
            findings.extend(self.test_workflow_bypass())
            findings.extend(self.test_blind_ssrf())

        return findings