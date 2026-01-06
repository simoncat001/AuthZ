from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class AuthzCheck(BaseModel):
    user_id: int
    role: str  # SUPER_ADMIN / DEPARTMENT_ADMIN / PROJECT_ADMIN / GROUP_ADMIN
    scope_type: str  # system / department / project / group
    scope_id: Optional[int]


class AuthzResult(BaseModel):
    allowed: bool


class RoleAssignment(BaseModel):
    user_id: int
    role: str
    scope_type: str
    scope_id: Optional[int]
    granted_by: Optional[int]
    granted_at: Optional[datetime]


class RoleGrant(BaseModel):
    user_id: int
    role: str
    scope_type: str
    scope_id: Optional[int]
    granted_by: int


class RoleGrantItem(BaseModel):
    role: str
    scope_type: str
    scope_id: Optional[int]


class RoleGrantBatch(BaseModel):
    user_id: int
    granted_by: int
    items: List[RoleGrantItem]


class RoleRevoke(BaseModel):
    user_id: int
    role: str
    scope_type: str
    scope_id: Optional[int]


class RoleList(BaseModel):
    items: List[RoleAssignment]


class ScopeItem(BaseModel):
    scope_id: Optional[int]
    role: str


class ScopeList(BaseModel):
    items: List[ScopeItem]
