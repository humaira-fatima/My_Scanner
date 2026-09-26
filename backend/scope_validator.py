import fnmatch
from urllib.parse import urlparse
import logging

logger = logging.getLogger("ScopeValidator")

class ScopeValidator:
    def __init__(self, target_domain: str, extra_wildcards: list = None, excluded_patterns: list = None):
        """
        Initializes scope rules for a specific target domain.
        Automatically includes the base domain and its wildcard subdomain by default.
        """
        base = target_domain.lower().strip()
        self.allowed_wildcards = [base, f"*.{base}"]
        
        if extra_wildcards:
            self.allowed_wildcards.extend([w.lower().strip() for w in extra_wildcards])
            
        self.excluded_patterns = [e.lower().strip() for e in (excluded_patterns or [])]

    def is_in_scope(self, url_or_domain: str) -> bool:
        """
        Evaluates whether a given URL, subdomain, or asset strictly matches 
        the target program's bounty scope rules.
        """
        if not url_or_domain:
            return False

        # Normalize input (extract hostname if it's a full URL)
        parsed = urlparse(url_or_domain)
        hostname = parsed.netloc if parsed.netloc else url_or_domain
        hostname = hostname.lower().split(":")[0]  # Strip port if present

        # 1. Check Exclusion Blacklists first (e.g., staging, third-party CDNs)
        for pattern in self.excluded_patterns:
            if fnmatch.fnmatch(hostname, pattern):
                logger.debug(f"Asset {hostname} matched exclusion pattern {pattern}. Out of scope.")
                return False

        # 2. Check Inclusion Whitelists / Wildcards
        for pattern in self.allowed_wildcards:
            if fnmatch.fnmatch(hostname, pattern):
                return True

        logger.debug(f"Asset {hostname} did not match any allowed wildcards. Out of scope.")
        return False