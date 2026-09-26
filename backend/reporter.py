import logging
from jinja2 import Template
from sqlalchemy.orm import Session
from models import Finding, TargetDomain

logger = logging.getLogger("Reporter")

# Standardized HackerOne Bug Bounty Markdown Template
H1_TEMPLATE = """
**Summary:**
{{ finding.title }} was detected on `{{ target.domain_name }}`.

**Description:**
Automated differential analysis and dependency scanning identified a {{ finding.severity }}-severity issue at the following endpoint:
`{{ finding.endpoint }}`

**Steps To Reproduce:**
1. Navigate to the affected endpoint or inspect the JavaScript bundle: `{{ finding.endpoint }}`
2. Analyze the component variables, endpoints, or dependency versions.
3. Observe the behavior detailed in the JSON metadata below.

**Impact:**
Depending on the specific vulnerability context (e.g., IDOR, BOLA, or vulnerable OSV dependency), this could allow an attacker to read unauthorized data, manipulate frontend logic, or exploit known CVEs.

**Reference Metadata (JSON):**
""" + "```json\n{{ finding.details_json }}\n```"

class ReportGenerator:
    def __init__(self, db: Session):
        self.db = db
        # Initialize the Jinja2 template
        self.template = Template(H1_TEMPLATE.strip())

    def generate_hackerone_report(self, finding_id: int):
        """Renders the finding into a HackerOne Markdown format and saves it to the DB."""
        finding = self.db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            logger.error(f"Finding ID {finding_id} not found.")
            return None

        target = self.db.query(TargetDomain).filter(TargetDomain.id == finding.target_id).first()
        if not target:
            logger.error("Target domain not found for this finding.")
            return None
            
        # 1. Render the Markdown template with Jinja2
        rendered_report = self.template.render(finding=finding, target=target)
        
        # 2. Store the generated string directly in finding.draft_report
        finding.draft_report = rendered_report
        self.db.commit()
        
        logger.info(f"Successfully generated HackerOne report for Finding ID {finding.id}.")
        return rendered_report