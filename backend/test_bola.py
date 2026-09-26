# test_bola.py
import asyncio
from database import SessionLocal
from idor_engine import run_bola_scan

async def test():
    db = SessionLocal()
    try:
        print("[*] Testing BOLA scan logic...")
        # Pointing to a test endpoint; since the endpoint is offline or mocked,
        # it will verify database querying, token extraction, and error handling safely.
        result = await run_bola_scan(
            db=db,
            target_id=1,
            endpoint_url="https://httpbin.org/get?id={ID}",
            resource_id="1001"
        )
        print(f"[+] Scan Result: {result}")
    finally:
        db.close()

if __name__ == "__main__":
    asyncio.run(test())