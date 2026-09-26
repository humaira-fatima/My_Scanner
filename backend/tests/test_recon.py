from database import SessionLocal
from models import TargetDomain, Asset
from http_client import SecureScannerClient
from recon import ReconEngine

# 1. Open an isolated database session
db = SessionLocal()

print("--- TESTING RECONNAISSANCE ENGINE (PHASE 2A) ---")

# 2. Select or create a whitelisted target domain in the database
# Using 'hackerone.com' as a real-world target for public certificate & archive queries
domain_name = "httpbin.org"
target = db.query(TargetDomain).filter(TargetDomain.domain_name == domain_name).first()

if not target:
    print(f"Adding '{domain_name}' to target_domains table...")
    target = TargetDomain(domain_name=domain_name, is_in_scope=True)
    db.add(target)
    db.commit()

# 3. Instantiate the HTTP client and Recon engine
client = SecureScannerClient(db)
recon = ReconEngine(db, client)

# 4. Run Subdomain Discovery via crt.sh API
print(f"\n[1/2] Fetching subdomains for {domain_name} from crt.sh...")
recon.discover_subdomains(domain_name)

# 5. Run JS Endpoint Discovery via Wayback Machine CDX API
print(f"\n[2/2] Fetching historical JS files for {domain_name} from Wayback Machine...")
recon.discover_js_endpoints(domain_name)

# 6. Verify and print database results
print("\n--- DATABASE VERIFICATION ---")
subdomains = db.query(Asset).filter(Asset.target_id == target.id, Asset.asset_type == "subdomain").all()
js_files = db.query(Asset).filter(Asset.target_id == target.id, Asset.asset_type == "js_file").all()

print(f"Total Subdomains saved in DB: {len(subdomains)}")
if subdomains:
    print("Sample Subdomains Discovered:")
    for sub in subdomains[:5]:
        print(f"  - {sub.value}")

print(f"\nTotal JS Files saved in DB: {len(js_files)}")
if js_files:
    print("Sample JS Endpoints Discovered:")
    for js in js_files[:5]:
        print(f"  - {js.value}")

db.close()
print("\n--- RECON VERIFICATION COMPLETE ---")