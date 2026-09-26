# test_dom.py
import asyncio
from database import SessionLocal
from dom_scanner import run_dom_scanner

async def test():
    db = SessionLocal()
    try:
        # Testing against a known safe target or a deliberate vulnerable lab 
        url = "https://httpbin.org/get" 
        result = await run_dom_scanner(db, 1, url)
        print(f"[+] DOM Scan Result: {result}")
    finally:
        db.close()

if __name__ == "__main__":
    asyncio.run(test())