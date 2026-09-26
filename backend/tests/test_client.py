from database import SessionLocal
from models import BountyProfile, TargetDomain
from http_client import SecureScannerClient

# 1. Open database session
db = SessionLocal()

print("--- TESTING PHASE 1 ARCHITECTURE ---")

# 2. Insert a dummy active BountyProfile if one doesn't exist
profile = db.query(BountyProfile).filter(BountyProfile.is_active == True).first()
if not profile:
    print("Creating active HackerOne Bounty Profile...")
    profile = BountyProfile(
        platform_name="HackerOne",
        username="humaira_fatima",
        email_alias="humaira_fatima@wearehackerone.com",
        custom_header_key="X-HackerOne-Research",
        user_agent_string="Mozilla/5.0 My_Scanner (HackerOne Research: humaira_fatima@wearehackerone.com)",
        is_active=True
    )
    db.add(profile)
    db.commit()

# 3. Insert a whitelisted target domain into TargetDomain
target = db.query(TargetDomain).filter(TargetDomain.domain_name == "httpbin.org").first()
if not target:
    print("Adding 'httpbin.org' to TargetDomain whitelist...")
    target = TargetDomain(domain_name="httpbin.org", is_in_scope=True)
    db.add(target)
    db.commit()

# 4. Instantiate SecureScannerClient and run test requests
client = SecureScannerClient(db)

print("\n[TEST 1] In-Scope Request to httpbin.org/headers...")
res = client.execute_request("GET", "https://httpbin.org/headers")
if res:
    print(f"Status Code: {res.status_code}")
    print("Headers returned by server (showing injected H1 identification):")
    print(res.text)

print("\n[TEST 2] Out-of-Scope Request Guard Test (example.com)...")
res_out = client.execute_request("GET", "https://example.com/api")

print("\n[TEST 3] Blacklisted Route Test (/checkout)...")
res_black = client.execute_request("GET", "https://httpbin.org/checkout")

db.close()
print("\n--- PHASE 1 VERIFICATION COMPLETE ---")