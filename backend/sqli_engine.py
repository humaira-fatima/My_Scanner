import httpx
import re
import urllib.parse
from typing import Dict, Any

SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"unclosed quotation mark after the character string",
    r"pg_query\(\): query failed",
    r"sqlite3::sqlexception",
    r"ora-[0-9]{5}",
    r"microsoft ole db provider for sql server"
]

async def test_error_sqli(client: httpx.AsyncClient, target_url: str) -> Dict[str, Any]:
    """
    Injects single quotes and SQL break characters into URL parameters 
    and checks for raw database engine error disclosures.
    """
    parsed = urllib.parse.urlparse(target_url)
    params = urllib.parse.parse_qs(parsed.query)
    
    if not params:
        return {"status": "skipped"}

    for param in params:
        test_params = params.copy()
        test_params[param] = f"{test_params[param][0]}'"
        
        new_query = urllib.parse.urlencode(test_params, doseq=True)
        fuzzed_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        
        try:
            res = await client.get(fuzzed_url)
            for error_regex in SQL_ERRORS:
                if re.search(error_regex, res.text, re.IGNORECASE):
                    return {
                        "status": "vulnerable",
                        "vulnerability": "Error-Based SQL Injection",
                        "parameter": param,
                        "endpoint": fuzzed_url,
                        "pattern_matched": error_regex
                    }
        except Exception:
            continue

    return {"status": "secure"}