from fastapi import APIRouter, Depends, HTTPException, Query

from app.database import get_db
from app.schemas import (
    AuthzCheck,
    AuthzResult,
    RoleGrant,
    RoleGrantBatch,
    RoleList,
    RoleRevoke,
    ScopeList,
)
from app.service import AuthzService

router = APIRouter()


@router.get("/health")
def health():
    """健康检查接口：用于探活，返回服务状态。"""
    return {"status": "ok"}


@router.post("/authz/check", response_model=AuthzResult)
def check_authz(req: AuthzCheck, db=Depends(get_db)):
    """权限检查接口：验证用户在指定范围内是否拥有目标管理员角色。"""
    svc = AuthzService(db)
    return AuthzResult(
        allowed=svc.check(
            req.user_id,
            req.role,
            req.scope_type,
            req.scope_id,
        )
    )


@router.post("/authz/roles")
def grant_role(req: RoleGrant, db=Depends(get_db)):
    """单条授权接口：为用户授予某个管理员角色（含层级校验）。"""
    svc = AuthzService(db)
    allowed, reason = svc.can_grant(
        req.granted_by,
        req.role,
        req.scope_type,
        req.scope_id,
    )
    if not allowed:
        status_code = 403
        if reason in {
            "role_scope_mismatch",
            "unsupported_scope_type",
            "scope_id_required",
            "project_not_found",
            "group_not_found",
        }:
            status_code = 400
        raise HTTPException(status_code=status_code, detail=reason)
    svc.grant_role(
        req.user_id,
        req.role,
        req.scope_type,
        req.scope_id,
        req.granted_by,
    )
    return {"status": "ok"}


@router.post("/authz/roles/batch")
def grant_roles_batch(req: RoleGrantBatch, db=Depends(get_db)):
    """批量授权接口：一次请求授予同一用户多个管理员角色（含层级校验）。"""
    svc = AuthzService(db)
    for item in req.items:
        allowed, reason = svc.can_grant(
            req.granted_by,
            item.role,
            item.scope_type,
            item.scope_id,
        )
        if not allowed:
            status_code = 403
            if reason in {
                "role_scope_mismatch",
                "unsupported_scope_type",
                "scope_id_required",
                "project_not_found",
                "group_not_found",
            }:
                status_code = 400
            raise HTTPException(status_code=status_code, detail=reason)
    svc.grant_roles_batch(
        req.user_id,
        [
            {
                "role": item.role,
                "scope_type": item.scope_type,
                "scope_id": item.scope_id,
            }
            for item in req.items
        ],
        req.granted_by,
    )
    return {"status": "ok"}


@router.delete("/authz/roles")
def revoke_role(req: RoleRevoke, db=Depends(get_db)):
    """撤销授权接口：移除用户在某个范围内的管理员角色。"""
    svc = AuthzService(db)
    svc.revoke_role(
        req.user_id,
        req.role,
        req.scope_type,
        req.scope_id,
    )
    return {"status": "ok"}


@router.get("/authz/roles", response_model=RoleList)
def list_roles(
    user_id: int | None = Query(default=None),
    role: str | None = Query(default=None),
    scope_type: str | None = Query(default=None),
    scope_id: int | None = Query(default=None),
    db=Depends(get_db),
):
    """授权查询接口：按条件查询管理员角色分配列表。"""
    svc = AuthzService(db)
    return RoleList(
        items=svc.list_roles(
            user_id=user_id,
            role=role,
            scope_type=scope_type,
            scope_id=scope_id,
        )
    )


@router.get("/authz/users/{user_id}/groups", response_model=ScopeList)
def list_user_groups(user_id: int, db=Depends(get_db)):
    """用户小组管理员列表接口：返回用户管理的小组范围。"""
    svc = AuthzService(db)
    return ScopeList(items=svc.list_user_scopes(user_id, "group"))


@router.get("/authz/users/{user_id}/projects", response_model=ScopeList)
def list_user_projects(user_id: int, db=Depends(get_db)):
    """用户项目管理员列表接口：返回用户管理的项目范围。"""
    svc = AuthzService(db)
    return ScopeList(items=svc.list_user_scopes(user_id, "project"))


@router.get("/authz/users/{user_id}/departments", response_model=ScopeList)
def list_user_departments(user_id: int, db=Depends(get_db)):
    """用户部门管理员列表接口：返回用户管理的部门范围。"""
    svc = AuthzService(db)
    return ScopeList(items=svc.list_user_scopes(user_id, "department"))
