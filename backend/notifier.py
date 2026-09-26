import os
import httpx
import logging
from typing import Optional
from dotenv import load_dotenv
from models import Finding

# Load environment variables from the .env file
load_dotenv()

logger = logging.getLogger("DiscordNotifier")

class DiscordNotifier:
    def __init__(self, webhook_url: Optional[str] = None):
        # Fetch it from the argument if provided, otherwise securely fetch from .env
        self.webhook_url = webhook_url or os.getenv("DISCORD_WEBHOOK_URL")

    def notify_finding(self, finding: Finding):
        """Dispatches an alert to Discord for high-value endpoints or JS changes."""
        if not self.webhook_url:
            logger.warning("No Discord webhook URL configured. Skipping alert.")
            return

        if finding.severity not in ["Medium", "High", "Critical"]:
            return

        color_map = {"Critical": 15158332, "High": 15105570, "Medium": 1752220}
        
        payload = {
            "content": "🚨 @here **New High-Value Recon Alert Found!**",
            "username": "My_Scanner Alert Bot",
            "embeds": [
                {
                    "title": f"[{finding.severity.upper()}] {finding.title}",
                    "color": color_map.get(finding.severity, 3447003),
                    "fields": [
                        {"name": "Target Endpoint", "value": f"`{finding.endpoint}`", "inline": False},
                        {"name": "Status", "value": "Ready for HackerOne Submission Review", "inline": False},
                    ],
                    "footer": {"text": "My_Scanner Recon Engine"}
                }
            ]
        }

        try:
            response = httpx.post(self.webhook_url, json=payload, timeout=10.0)
            response.raise_for_status()
            logger.info(f"Discord alert successfully sent for Finding ID: {finding.id}")
        except Exception as e:
            logger.error(f"Failed to send Discord alert: {e}")

    def notify_scan_complete(self, target: str, findings_count: int):
        """
        Sends an automated embedded alert to Discord when a Nuclei scan completes.
        This provides a definitive 'finished' signal even if zero vulnerabilities are found.
        """
        if not self.webhook_url:
            logger.warning("No Discord webhook URL configured. Skipping scan completion alert.")
            return

        # Set embed color: Red (16711680) if vulnerabilities found, Green (65280) if clean
        color = 16711680 if findings_count > 0 else 65280 
        
        # Construct the Discord JSON payload for the completion status
        payload = {
            "username": "My_Scanner Alert Bot",
            "embeds": [
                {
                    "title": f"Scan Completed: {target}",
                    "description": f"Active scanning pipeline has successfully finished executing for **{target}**.",
                    "color": color,
                    "fields": [
                        {
                            "name": "Total Findings",
                            "value": str(findings_count),
                            "inline": True
                        }
                    ],
                    "footer": {
                        "text": "My_Scanner Automated Engine"
                    }
                }
            ]
        }

        try:
            # Using synchronous HTTPX to match your existing architecture
            response = httpx.post(self.webhook_url, json=payload, timeout=10.0)
            response.raise_for_status()
            logger.info(f"Scan completion alert successfully sent for target: {target}")
        except Exception as e:
            logger.error(f"Failed to send scan completion alert: {e}")