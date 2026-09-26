# test_js_miner.py
import asyncio
from database import SessionLocal
from js_miner import analyze_js_asset

async def test():
    db = SessionLocal()
    try:
        # Test against a sample JS file (e.g., jQuery or public JS asset)
        js_url = "https://code.jquery.com/jquery-3.6.0.min.js"
        print(f"[*] Mining JS endpoints from {js_url}...")
        result = await analyze_js_asset(db, target_id=1, js_url=js_url)
        print(f"[+] Result: {result}")
    finally:
        db.close()

if __name__ == "__main__":
    asyncio.run(test())