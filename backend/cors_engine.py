import httpx
from typing import Dict, Any

async def test_cors_misconfig(client: httpx.AsyncClient, target_url: str) -> Dict[str, Any]:
    """
    Tests if an API endpoint trusts arbitrary origins with authenticated credentials.
    """
    evil_origin = "https://evil-attacker.com"
    headers = {"Origin": evil_origin}
    
    try:
        res = await client.get(target_url, headers=headers)
        
        allow_origin = res.headers.get("Access-Control-Allow-Origin", "")
        allow_credentials = res.headers.get("Access-Control-Allow-Credentials", "").lower()
        
        if allow_origin == evil_origin and allow_credentials == "true":
            return {
                "status": "vulnerable",
                "vulnerability": "CORS Misconfiguration (Arbitrary Origin Trust with Credentials)",
                "endpoint": target_url
            }
        elif allow_origin == "*" and allow_credentials == "true":
            return {
                "status": "vulnerable",
                "vulnerability": "CORS Misconfiguration (Wildcard Origin with Credentials)",
                "endpoint": target_url
            }
    except Exception:
        pass
        
    return {"status": "secure"}