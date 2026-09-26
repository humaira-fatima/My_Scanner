from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

# Bounty Profile Schemas
class BountyProfileBase(BaseModel):
    platform_name: str
    username: str
    email_alias: str
    custom_header_key: str
    user_agent_string: str
    is_active: Optional[bool] = False

class BountyProfileCreate(BountyProfileBase):
    pass

class BountyProfileResponse(BountyProfileBase):
    id: int

    class Config:
        from_attributes = True

# Target Domain Schemas
class TargetDomainBase(BaseModel):
    domain_name: str
    platform: Optional[str] = "HackerOne"
    is_in_scope: Optional[bool] = True

class TargetDomainCreate(TargetDomainBase):
    pass

class TargetDomainResponse(TargetDomainBase):
    id: int
    created_at: datetime
    auth_token_a: Optional[str] = None
    auth_token_b: Optional[str] = None

    class Config:
        from_attributes = True

# Session Update Schema
class TargetSessionUpdate(BaseModel):
    auth_token_a: Optional[str] = None
    auth_token_b: Optional[str] = None

# Finding Schemas
class FindingBase(BaseModel):
    title: str
    severity: str
    endpoint: str
    details_json: Optional[str] = None
    draft_report: Optional[str] = None
    is_verified: Optional[bool] = False

class FindingResponse(FindingBase):
    id: int
    target_id: int
    discovered_at: datetime

    class Config:
        from_attributes = True