from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

class BountyProfile(Base):
    """
    DATABASE TABLE: bounty_profiles
    PURPOSE: Manages bug bounty platform headers (HackerOne, Bugcrowd, Intigriti).
    
    IDENTITY HEADER INJECTION DATA FLOW:
    - Stores header keys, username aliases, and custom User-Agent strings.
    - The http_client wrapper queries 'is_active=True' before launching scan jobs
      to inject these precise identity headers into every outgoing HTTP packet.
    """
    __tablename__ = "bounty_profiles"

    id = Column(Integer, primary_key=True, index=True)
    platform_name = Column(String, index=True, nullable=False) # e.g., 'HackerOne'
    username = Column(String, unique=True, index=True, nullable=False)                               # e.g., 'your_h1_username'
    email_alias = Column(String, nullable=False)                            # e.g., 'user@wearehackerone.com'
    custom_header_key = Column(String, nullable=False)                     # e.g., 'X-HackerOne-Research'
    user_agent_string = Column(String, nullable=False)                     # Custom platform User-Agent
    is_active = Column(Boolean, default=False, nullable=False)              # Toggle for active HTTP client
    created_at = Column(DateTime, default=datetime.utcnow)

class TargetDomain(Base):
    """
    DATABASE TABLE: target_domains
    PURPOSE: Maintains target whitelists for Scope Guard middleware and platform tagging.
    
    SAFETY & SCOPE GUARD DATA FLOW:
    - Before http_client fires a scan request, it verifies the host against this table.
    - If 'is_in_scope' is False or missing, the request is instantly dropped.
    """
    __tablename__ = "target_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain_name = Column(String, unique=True, index=True, nullable=False)  # e.g., 'target.com'
    platform = Column(String, default="HackerOne", nullable=False)          # 'HackerOne', 'Bugcrowd', 'Intigriti', 'Independent'
    is_in_scope = Column(Boolean, default=True, nullable=False)             # Whitelist enforcement
    
    # New columns for BOLA/IDOR session testing
    auth_token_a = Column(Text, nullable=True) 
    auth_token_b = Column(Text, nullable=True) 
    
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    assets = relationship("Asset", back_populates="target", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="target", cascade="all, delete-orphan")

class Asset(Base):
    """
    DATABASE TABLE: assets
    PURPOSE: Tracks discovered infrastructure, unlinked routes, and JavaScript bundles.
    
    RECON & MONITORING DATA FLOW:
    - Populated by recon modules querying crt.sh and Wayback Machine APIs.
    - js_monitor computes 'content_hash' to perform diffs and flag newly deployed endpoints.
    """
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("target_domains.id"), nullable=False)
    asset_type = Column(String, nullable=False)                            # 'subdomain', 'endpoint', 'js_file'
    value = Column(Text, nullable=False)                                   # e.g., 'https://api.target.com/v1/app.js'
    content_hash = Column(String, nullable=True)                           # Hash for JS diffing
    discovered_at = Column(DateTime, default=datetime.utcnow)

    target = relationship("TargetDomain", back_populates="assets")

class Finding(Base):
    """
    DATABASE TABLE: findings
    PURPOSE: Stores vulnerabilities, flagged JS changes, and pre-written Jinja2 reports.
    
    REPORT GENERATION DATA FLOW:
    - Automatically populated when JS diffs, Google OSV API matches, or secrets are found.
    - Jinja2 engine renders findings directly into the 'draft_report' column.
    - Ready for copy-pasting into submission portals upon manual Burp Suite verification.
    """
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("target_domains.id"), nullable=False)
    title = Column(String, nullable=False)                                 # e.g., 'New API Endpoint Discovered'
    severity = Column(String, nullable=False)                              # 'Low', 'Medium', 'High', 'Critical'
    endpoint = Column(Text, nullable=False)                                # Affected URL
    details_json = Column(Text, nullable=True)                             # Raw technical response metadata
    draft_report = Column(Text, nullable=True)                             # Pre-formatted Jinja2 Markdown report
    is_verified = Column(Boolean, default=False)                           # Manual PoC verification state
    discovered_at = Column(DateTime, default=datetime.utcnow)

    target = relationship("TargetDomain", back_populates="findings")