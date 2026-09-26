import httpx
import re
import urllib.parse
from typing import Dict, Any

XSS_CANARY = "xss31337"
PROBE_PAYLOAD = f"'{XSS_CANARY}\"><svg/onload=alert(1)>"

async def test_reflected_xss(client: httpx.AsyncClient, target_url: str) -> Dict[str, Any]:
    """
    Fuzzes all query parameters in target_url with an unescaped canary string 
    and checks if it reflects back unencoded in the HTTP response body.
    """
    parsed = urllib.parse.urlparse(target_url)
    params = urllib.parse.parse_qs(parsed.query)
    
    if not params:
        return {"status": "skipped", "reason": "No query parameters found"}

    for param in params:
        test_params = params.copy()
        test_params[param] = PROBE_PAYLOAD
        
        # Rebuild query string with payload
        new_query = urllib.parse.urlencode(test_params, doseq=True)
        fuzzed_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        
        try:
            res = await client.get(fuzzed_url)
            if res.status_code == 200 and PROBE_PAYLOAD in res.text:
                # Confirm response Content-Type is HTML/XML (not raw JSON or plain text)
                content_type = res.headers.get("Content-Type", "").lower()
                if "html" in content_type or "xml" in content_type:
                    return {
                        "status": "vulnerable",
                        "vulnerability": "Reflected Cross-Site Scripting (XSS)",
                        "parameter": param,
                        "endpoint": fuzzed_url
                    }
        except Exception:
            continue

    return {"status": "secure"}