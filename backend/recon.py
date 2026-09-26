import hashlib
import json
import logging
import asyncio
import re
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse
import httpx
from sqlalchemy.orm import Session

from models import TargetDomain, Asset, Finding
from http_client import SecureScannerClient
from scope_validator import ScopeValidator
from notifier import DiscordNotifier

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ReconEngine")

# Common secret regex patterns for JS mining
SECRET_PATTERNS = {
    "AWS Access Key": r"(?i)AKIA[0-9A-Z]{16}",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{20,}",
    "Generic API Key / Token": r"""(?i)(?:api_key|apikey|secret_key|secret|token)\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,})["']""",
    "Internal Endpoint / Admin Route": r"""["'](/admin_[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)["']""",
    "Staging Service URL": r"""https?://[a-zA-Z0-9_\-]+\.(?:corp\.local|internal|staging)"""
}


def save_finding_uniquely(
    db: Session, 
    target_id: int, 
    title: str, 
    endpoint: str, 
    severity: str, 
    details_json: str, 
    draft_report: str
):
    """Checks if an identical finding already exists for this target endpoint."""
    existing = db.query(Finding).filter(
        Finding.target_id == target_id,
        Finding.endpoint == endpoint,
        Finding.title == title
    ).first()

    if existing:
        existing.details_json = details_json
        existing.severity = severity
        existing.draft_report = draft_report
        db.commit()
        return existing, False

    new_finding = Finding(
        target_id=target_id,
        title=title,
        severity=severity,
        endpoint=endpoint,
        details_json=details_json,
        draft_report=draft_report,
        is_verified=True
    )
    db.add(new_finding)
    db.commit()
    db.refresh(new_finding)
    return new_finding, True


def format_target_url(domain: str) -> str:
    """Formats domain to a valid base HTTP/HTTPS URL."""
    if domain.startswith("http://") or domain.startswith("https://"):
        return domain.rstrip("/")
    if "127.0.0.1" in domain or "localhost" in domain:
        return f"http://{domain}".rstrip("/")
    return f"https://{domain}".rstrip("/")


class ReconEngine:
    def __init__(self, db: Session, client: SecureScannerClient):
        self.db = db
        self.client = client
        self.notifier = DiscordNotifier()
        self.osint_headers = {
            getattr(self.client.active_profile, "custom_header_key", "X-Research-User"): getattr(self.client.active_profile, "username", "Scanner"),
            "X-Research-Email": getattr(self.client.active_profile, "email_alias", "researcher@bugbounty.local"),
            "User-Agent": getattr(self.client.active_profile, "user_agent_string", "My_Scanner_Recon_Engine/1.0"),
        }

    async def discover_subdomains(self, domain: str, retries: int = 3):
        logger.info(f"Starting subdomain enumeration for {domain} via crt.sh...")
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        validator = ScopeValidator(target_domain=domain)

        async with httpx.AsyncClient(timeout=20.0, verify=False) as async_client:
            for attempt in range(retries):
                try:
                    response = await async_client.get(url, headers=self.osint_headers)
                    if response.status_code == 502:
                        await asyncio.sleep(3)
                        continue

                    response.raise_for_status()
                    data = response.json()

                    subdomains = set()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        if name_value and "*" not in name_value:
                            for sub in name_value.split("\n"):
                                subdomains.add(sub.strip())

                    target = self.db.query(TargetDomain).filter(TargetDomain.domain_name == domain).first()
                    if target:
                        new_assets = 0
                        for sub in subdomains:
                            if not validator.is_in_scope(sub):
                                continue

                            exists = self.db.query(Asset).filter(Asset.value == sub).first()
                            if not exists:
                                new_asset = Asset(target_id=target.id, asset_type="subdomain", value=sub)
                                self.db.add(new_asset)
                                new_assets += 1
                        self.db.commit()
                        logger.info(f"Saved {new_assets} in-scope subdomains to the database.")
                    return

                except (httpx.HTTPError, ValueError) as e:
                    logger.debug(f"crt.sh enumeration attempt {attempt + 1} failed: {e}")
                    await asyncio.sleep(3)

        logger.error(f"Failed to fetch subdomains from crt.sh for {domain}.")

    async def discover_js_endpoints(self, domain: str, retries: int = 3):
        """Discovers JS files using direct HTML parsing fallback for local targets and Wayback for remote targets."""
        logger.info(f"Starting JS file discovery for target: {domain}")
        target = self.db.query(TargetDomain).filter(TargetDomain.domain_name == domain).first()
        if not target:
            return

        discovered_js_urls = set()
        base_url = format_target_url(domain)

        # 1. Direct Crawl: Scrape HTML <script src="..."> tags (Crucial for 127.0.0.1 / local testbeds)
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as async_client:
                res = await async_client.get(base_url, headers=self.osint_headers)
                if res.status_code == 200:
                    script_srcs = re.findall(r"""<script[^>]+src=["']([^"']+)["']""", res.text, re.IGNORECASE)
                    for src in script_srcs:
                        full_js_url = urljoin(base_url, src)
                        discovered_js_urls.add(full_js_url)
        except Exception as err:
            logger.debug(f"Direct HTML JS crawling failed for {base_url}: {err}")

        # 2. Wayback Machine Discovery (for public targets)
        if "127.0.0.1" not in domain and "localhost" not in domain:
            archive_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&filter=mimetype:application/javascript&collapse=urlkey"
            async with httpx.AsyncClient(timeout=15.0, verify=False) as async_client:
                try:
                    response = await async_client.get(archive_url, headers=self.osint_headers)
                    if response.status_code == 200:
                        data = response.json()
                        if isinstance(data, list) and len(data) > 1:
                            for row in data[1:]:
                                if len(row) > 2:
                                    discovered_js_urls.add(row[2])
                except Exception as e:
                    logger.debug(f"Wayback JS fetch failed: {e}")

        # Save discovered JS URLs to Assets
        js_count = 0
        for js_url in discovered_js_urls:
            exists = self.db.query(Asset).filter(Asset.target_id == target.id, Asset.value == js_url).first()
            if not exists:
                new_asset = Asset(target_id=target.id, asset_type="js_file", value=js_url)
                self.db.add(new_asset)
                js_count += 1
        self.db.commit()
        logger.info(f"Saved {js_count} new JS files to assets for {domain}.")

    async def mine_js_secrets(self, domain: str):
        """Downloads discovered JS assets and runs regex secret extraction (JS Miner)."""
        logger.info(f"[*] Executing JS Miner secret extraction for target: {domain}")
        target = self.db.query(TargetDomain).filter(TargetDomain.domain_name == domain).first()
        if not target:
            return

        # Ensure JS assets exist by triggering discovery first
        await self.discover_js_endpoints(domain)

        js_assets = self.db.query(Asset).filter(
            Asset.target_id == target.id,
            Asset.asset_type == "js_file"
        ).all()

        if not js_assets:
            logger.info("No JS assets found to mine.")
            return

        async with httpx.AsyncClient(timeout=15.0, verify=False) as async_client:
            for asset in js_assets:
                js_url = asset.value
                try:
                    res = await async_client.get(js_url, headers=self.osint_headers)
                    if res.status_code != 200:
                        continue

                    js_content = res.text

                    for secret_type, pattern in SECRET_PATTERNS.items():
                        matches = re.findall(pattern, js_content)
                        if matches:
                            unique_matches = list(set(matches))
                            for match in unique_matches:
                                found_val = match if isinstance(match, str) else str(match)
                                
                                title = f"Sensitive Secret Exposure ({secret_type}) in JS Bundle"
                                details = {
                                    "secret_type": secret_type,
                                    "matched_key": found_val,
                                    "js_file_url": js_url
                                }
                                draft = (
                                    f"### Hardcoded Secret Identified in JS File\n\n"
                                    f"- **Secret Type:** `{secret_type}`\n"
                                    f"- **Exposed Value:** `{found_val}`\n"
                                    f"- **Source File:** `{js_url}`\n\n"
                                    f"#### Remediation:\n"
                                    f"Remove sensitive keys from client-accessible static bundles."
                                )

                                finding, is_new = save_finding_uniquely(
                                    db=self.db,
                                    target_id=target.id,
                                    title=title,
                                    endpoint=js_url,
                                    severity="High",
                                    details_json=json.dumps(details),
                                    draft_report=draft
                                )

                                if is_new:
                                    logger.info(f"[+] JS Miner found {secret_type} in {js_url}")
                                    self.notifier.notify_finding(finding)

                except Exception as err:
                    logger.error(f"Error mining JS file {js_url}: {err}")

    async def monitor_js_changes(self, domain: str, max_file_size_bytes: int = 5_000_000):
        logger.info(f"Starting JavaScript differential analysis for domain: {domain}")
        target = self.db.query(TargetDomain).filter(TargetDomain.domain_name == domain).first()
        if not target:
            return

        js_assets = self.db.query(Asset).filter(
            Asset.target_id == target.id, 
            Asset.asset_type == "js_file"
        ).all()
        if not js_assets:
            return

        for asset in js_assets:
            js_url = asset.value
            try:
                response = self.client.execute_request(method="GET", url=js_url)
                if response is None or response.status_code != 200:
                    continue

                content_bytes = response.content
                if len(content_bytes) > max_file_size_bytes:
                    continue

                current_text = response.text
                new_hash = hashlib.sha256(content_bytes).hexdigest()

                if asset.content_hash is None:
                    asset.content_hash = new_hash
                    self.db.commit()
                    continue

                if asset.content_hash != new_hash:
                    old_hash = asset.content_hash
                    added_lines = [line.strip() for line in current_text.splitlines() if line.strip()][:30]
                    diff_preview = "\n".join(added_lines)

                    details_payload = {
                        "asset_id": asset.id,
                        "js_url": js_url,
                        "old_hash": old_hash,
                        "new_hash": new_hash,
                        "diff_sample": diff_preview
                    }
                    report_template = (
                        f"### JavaScript Change Detected\n\n"
                        f"- **Asset URL:** `{js_url}`\n"
                        f"- **Old SHA256:** `{old_hash[:12]}...`\n"
                        f"- **New SHA256:** `{new_hash[:12]}...`\n\n"
                        f"#### Content Preview:\n```javascript\n{diff_preview}\n```\n"
                    )

                    finding_title = f"JavaScript Bundle Modified: {js_url.split('/')[-1] or js_url}"

                    finding, is_new = save_finding_uniquely(
                        db=self.db,
                        target_id=target.id,
                        title=finding_title,
                        endpoint=js_url,
                        severity="Low",
                        details_json=json.dumps(details_payload),
                        draft_report=report_template
                    )

                    asset.content_hash = new_hash
                    self.db.commit()

                    if is_new:
                        logger.info(f"NEW change finding recorded for {js_url}.")
                        self.notifier.notify_finding(finding)

            except Exception as e:
                logger.error(f"Error during JS change monitoring for {js_url}: {e}")
                self.db.rollback()

    async def scan_osv_vulnerabilities(self, domain: str, package_dependencies: List[Dict[str, str]], retries: int = 3):
        logger.info(f"Starting OSV vulnerability query for target domain: {domain}")
        target = self.db.query(TargetDomain).filter(TargetDomain.domain_name == domain).first()
        if not target:
            return

        osv_api_url = "https://api.osv.dev/v1/query"

        async with httpx.AsyncClient(timeout=15.0, verify=False) as async_client:
            for pkg in package_dependencies:
                pkg_name = pkg.get("name")
                pkg_version = pkg.get("version")
                ecosystem = pkg.get("ecosystem", "npm")
                if not pkg_name or not pkg_version:
                    continue

                query_payload = {"version": pkg_version, "package": {"name": pkg_name, "ecosystem": ecosystem}}
                response_data = None

                for attempt in range(retries):
                    try:
                        response = await async_client.post(osv_api_url, json=query_payload, headers=self.osint_headers)
                        if response.status_code == 404:
                            break
                        response.raise_for_status()
                        response_data = response.json()
                        break
                    except (httpx.HTTPError, ValueError):
                        await asyncio.sleep(2)

                if not response_data or "vulns" not in response_data:
                    continue

                for vuln in response_data.get("vulns", []):
                    try:
                        vuln_id = vuln.get("id", "UNKNOWN-ID")
                        severity = "Medium"

                        report_markdown = (
                            f"### Vulnerable Dependency: {pkg_name}@{pkg_version}\n"
                            f"- **Advisory ID:** `{vuln_id}`\n"
                            f"- **Severity:** `{severity}`"
                        )
                        details_json_payload = {
                            "package_name": pkg_name,
                            "package_version": pkg_version,
                            "osv_id": vuln_id
                        }
                        title = f"Vulnerable Dependency: {pkg_name}@{pkg_version} ({vuln_id})"
                        endpoint = f"https://{domain}/ (Dependency: {pkg_name}@{pkg_version})"

                        finding, is_new = save_finding_uniquely(
                            db=self.db,
                            target_id=target.id,
                            title=title,
                            endpoint=endpoint,
                            severity=severity,
                            details_json=json.dumps(details_json_payload),
                            draft_report=report_markdown
                        )

                        if is_new:
                            self.notifier.notify_finding(finding)

                    except Exception as parse_err:
                        logger.error(f"Error parsing OSV vulnerability record: {parse_err}")