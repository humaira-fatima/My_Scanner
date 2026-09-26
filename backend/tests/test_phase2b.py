from database import SessionLocal
from models import TargetDomain, Asset
from http_client import SecureScannerClient
from recon import ReconEngine

# 1. Open database session
db = SessionLocal()

print("--- TESTING PHASE 2B: JS DIFFING & OSV SCANNING ---")

# 2. Instantiate clients
client = SecureScannerClient(db)
recon = ReconEngine(db, client)

# 3. Test OSV Dependency Scanner
print("\n[1/2] Testing OSV Vulnerability Scanner...")
# We are feeding it lodash 4.17.15, which has known public CVEs, to trigger a positive finding.
dummy_dependencies = [
    {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
    {"name": "react", "version": "18.2.0", "ecosystem": "npm"} 
]
recon.scan_osv_vulnerabilities(domain="httpbin.org", package_dependencies=dummy_dependencies)

# 4. Test JavaScript Differential Analysis
print("\n[2/2] Testing JavaScript Differential Analysis...")
# This will fetch the JS files you saved previously and create their baseline hashes.
recon.monitor_js_changes(domain="httpbin.org")

# 5. Verify Findings in Database
print("\n--- DATABASE VERIFICATION (FINDINGS) ---")
from models import Finding
target = db.query(TargetDomain).filter(TargetDomain.domain_name == "httpbin.org").first()

if target:
    findings = db.query(Finding).filter(Finding.target_id == target.id).all()
    print(f"Total Findings saved in DB: {len(findings)}")
    
    for f in findings:
        print(f"\n[*] {f.severity} - {f.title}")
        print(f"    Preview: {f.draft_report[:100]}...")
else:
    print("Target httpbin.org not found. Run test_recon.py first.")

db.close()
print("\n--- PHASE 2B VERIFICATION COMPLETE ---")