from database import SessionLocal
from models import Finding
from reporter import ReportGenerator
from notifier import DiscordNotifier

# You can replace this with your real Discord Webhook URL later
WEBHOOK_URL = "https://discordapp.com/api/webhooks/1541978012914815098/udeuVoXA2Ya8PDvl5bCBXs5IXvMM_w740a6YbHAQpzGdMtCBp7EXuJBW7-p1yO7tTc38" 

def test_phase3a():
    db = SessionLocal()
    
    # 1. Grab the first finding from the database
    finding = db.query(Finding).first()
    if not finding:
        print("No findings in database. Run test_phase2b.py first.")
        return

    print(f"[*] Testing Phase 3A on Finding ID: {finding.id}")

    # 2. Test the Jinja2 Reporter
    reporter = ReportGenerator(db)
    generated_report = reporter.generate_hackerone_report(finding.id)
    
    print("\n--- GENERATED HACKERONE MARKDOWN ---")
    print(generated_report[:300] + "\n... [TRUNCATED] ...")
    print("------------------------------------\n")

    # 3. Test the Discord Notifier
    if WEBHOOK_URL:
        print("[*] Sending alert to Discord...")
        notifier = DiscordNotifier(webhook_url=WEBHOOK_URL)
        notifier.notify_finding(finding)
    else:
        print("[!] No Webhook URL provided. Skipping Discord alert test.")

    db.close()
    print("[*] Phase 3A Test Complete.")

if __name__ == "__main__":
    test_phase3a()