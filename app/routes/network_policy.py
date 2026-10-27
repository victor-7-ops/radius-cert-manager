"""REST API router for tenant network policy, roles, site bindings, and switches.

Implements B04 and B08 specifications:
- Scoped registry reads and administrative role grants
- Tenant-owned departments and network roles
- Role ON/OFF switches (tenant-wide and site-specific)
- Platform ceiling enforcement
- Site draft binding configuration and policy publication
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import db, network_policy as np

logger = logging.getLogger(__name__)


class CreateSubsidiaryRequest(BaseModel):
    code: str
    display_name: str


class CreateDepartmentRequest(BaseModel):
    code: str
    display_name: str


class CreateNetworkRoleRequest(BaseModel):
    code: str
    display_name: str
    description: str | None = None
    is_privileged: bool = False


class SwitchStateRequest(BaseModel):
    enabled: bool
    reason: str


class DraftBindingItem(BaseModel):
    subsidiary_id: str
    network_role_id: str
    vlan_id: int
    fallback_vlan_id: int | None = None
    platform_enabled: bool = True
    tenant_enabled: bool = True


class UpdateDraftRequest(BaseModel):
    expected_revision: int
    bindings: list[DraftBindingItem]
    reason: str


class PublishSitePolicyRequest(BaseModel):
    expected_revision: int
    reason: str


def _handle_domain_error(e: Exception):
    if isinstance(e, np.PolicyValidationError):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    elif isinstance(e, np.ForbiddenError):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    elif isinstance(e, np.ResourceNotFoundError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    elif isinstance(e, np.ConcurrencyError):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    raise e


def get_router(deps) -> APIRouter:
    router = APIRouter(prefix="/api/network", tags=["network-policy"])

    @router.get("/subsidiaries")
    def list_subsidiaries(
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session: Session = deps.get_db_session()
        try:
            if admin.role == db.AdminRole.super_admin:
                subs = session.scalars(
                    select(db.Subsidiary).where(db.Subsidiary.is_active.is_(True)).order_by(db.Subsidiary.display_name.asc())
                ).all()
            else:
                actor_sub_id = np.resolve_admin_subsidiary_id(admin, session)
                if not actor_sub_id:
                    return {"subsidiaries": []}
                sub = session.get(db.Subsidiary, actor_sub_id)
                subs = [sub] if sub and sub.is_active else []

            return {
                "subsidiaries": [
                    {
                        "id": s.id,
                        "code": s.code,
                        "display_name": s.display_name,
                        "is_active": s.is_active,
                        "created_at": s.created_at.isoformat() if s.created_at else None,
                    }
                    for s in subs
                ]
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.post("/subsidiaries", status_code=status.HTTP_201_CREATED)
    def create_subsidiary(
        payload: CreateSubsidiaryRequest,
        admin: db.Admin = Depends(deps.require_super_admin),
    ):
        session: Session = deps.get_db_session()
        try:
            sub = np.create_subsidiary(admin, payload.code, payload.display_name, session)
            session.commit()
            return {
                "id": sub.id,
                "code": sub.code,
                "display_name": sub.display_name,
                "is_active": sub.is_active,
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.get("/subsidiaries/{subsidiary_id}/departments")
    def list_departments(
        subsidiary_id: str,
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session: Session = deps.get_db_session()
        try:
            if not np.is_admin_in_scope(admin, subsidiary_id, session):
                raise np.ResourceNotFoundError("Subsidiary not found")

            depts = session.scalars(
                select(db.Department).where(
                    db.Department.subsidiary_id == subsidiary_id,
                    db.Department.is_active.is_(True),
                ).order_by(db.Department.display_name.asc())
            ).all()

            results = []
            for d in depts:
                # Get linked role IDs
                role_ids = session.scalars(
                    select(db.DepartmentRole.network_role_id).where(db.DepartmentRole.department_id == d.id)
                ).all()
                results.append({
                    "id": d.id,
                    "code": d.code,
                    "display_name": d.display_name,
                    "subsidiary_id": d.subsidiary_id,
                    "is_active": d.is_active,
                    "linked_role_ids": list(role_ids),
                })
            return {"departments": results}
        except Exception as e:
            _handle_domain_error(e)

    @router.post("/subsidiaries/{subsidiary_id}/departments", status_code=status.HTTP_201_CREATED, dependencies=[Depends(deps.require_write)])
    def create_department(
        subsidiary_id: str,
        payload: CreateDepartmentRequest,
        admin: db.Admin = Depends(deps.require_write),
    ):
        session: Session = deps.get_db_session()
        try:
            dept = np.create_department(admin, subsidiary_id, payload.code, payload.display_name, session)
            session.commit()
            return {
                "id": dept.id,
                "code": dept.code,
                "display_name": dept.display_name,
                "subsidiary_id": dept.subsidiary_id,
                "is_active": dept.is_active,
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.get("/subsidiaries/{subsidiary_id}/roles")
    def list_network_roles(
        subsidiary_id: str,
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session: Session = deps.get_db_session()
        try:
            if not np.is_admin_in_scope(admin, subsidiary_id, session):
                raise np.ResourceNotFoundError("Subsidiary not found")

            roles = session.scalars(
                select(db.NetworkRole).where(
                    db.NetworkRole.subsidiary_id == subsidiary_id,
                    db.NetworkRole.is_active.is_(True),
                ).order_by(db.NetworkRole.display_name.asc())
            ).all()

            return {
                "roles": [
                    {
                        "id": r.id,
                        "code": r.code,
                        "display_name": r.display_name,
                        "description": r.description,
                        "subsidiary_id": r.subsidiary_id,
                        "is_active": r.is_active,
                        "is_privileged": r.is_privileged,
                    }
                    for r in roles
                ]
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.post("/subsidiaries/{subsidiary_id}/roles", status_code=status.HTTP_201_CREATED, dependencies=[Depends(deps.require_write)])
    def create_network_role(
        subsidiary_id: str,
        payload: CreateNetworkRoleRequest,
        admin: db.Admin = Depends(deps.require_write),
    ):
        session: Session = deps.get_db_session()
        try:
            role = np.create_network_role(
                actor=admin,
                subsidiary_id=subsidiary_id,
                code=payload.code,
                display_name=payload.display_name,
                description=payload.description,
                is_privileged=payload.is_privileged,
                session=session,
            )
            session.commit()
            return {
                "id": role.id,
                "code": role.code,
                "display_name": role.display_name,
                "description": role.description,
                "subsidiary_id": role.subsidiary_id,
                "is_active": role.is_active,
                "is_privileged": role.is_privileged,
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.put("/departments/{department_id}/roles/{role_id}", dependencies=[Depends(deps.require_write)])
    def link_department_role(
        department_id: str,
        role_id: str,
        admin: db.Admin = Depends(deps.require_write),
    ):
        session: Session = deps.get_db_session()
        try:
            link = np.link_department_role(admin, department_id, role_id, session)
            session.commit()
            return {
                "department_id": link.department_id,
                "network_role_id": link.network_role_id,
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.put("/admins/{admin_id}/role-grants/{role_id}", dependencies=[Depends(deps.require_write)])
    def grant_role_to_admin(
        admin_id: str,
        role_id: str,
        admin: db.Admin = Depends(deps.require_write),
    ):
        session: Session = deps.get_db_session()
        try:
            grant = np.grant_role(admin, admin_id, role_id, session)
            session.commit()
            return {
                "admin_id": grant.admin_id,
                "network_role_id": grant.network_role_id,
                "granted_by": grant.granted_by,
                "granted_at": grant.granted_at.isoformat() if grant.granted_at else None,
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.delete("/admins/{admin_id}/role-grants/{role_id}", dependencies=[Depends(deps.require_write)])
    def revoke_role_grant_from_admin(
        admin_id: str,
        role_id: str,
        admin: db.Admin = Depends(deps.require_write),
    ):
        session: Session = deps.get_db_session()
        try:
            np.revoke_grant(admin, admin_id, role_id, session)
            session.commit()
            return {"revoked": True}
        except Exception as e:
            _handle_domain_error(e)

    @router.patch("/roles/{role_id}/state", dependencies=[Depends(deps.require_write)])
    def set_network_role_state(
        role_id: str,
        payload: SwitchStateRequest,
        admin: db.Admin = Depends(deps.require_write),
    ):
        session: Session = deps.get_db_session()
        try:
            role = np.set_network_role_tenant_state(
                admin, role_id, payload.enabled, payload.reason, session
            )
            session.commit()
            return {
                "id": role.id,
                "display_name": role.display_name,
                "is_active": role.is_active,
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.patch("/sites/{site_id}/roles/{role_id}/tenant-state", dependencies=[Depends(deps.require_write)])
    def set_site_binding_tenant_state(
        site_id: str,
        role_id: str,
        payload: SwitchStateRequest,
        admin: db.Admin = Depends(deps.require_write),
    ):
        session: Session = deps.get_db_session()
        try:
            binding = np.set_site_binding_tenant_state(
                admin, site_id, role_id, payload.enabled, payload.reason, session
            )
            session.commit()
            return {
                "site_id": binding.site_id,
                "subsidiary_id": binding.subsidiary_id,
                "network_role_id": binding.network_role_id,
                "tenant_enabled": binding.tenant_enabled,
                "platform_enabled": binding.platform_enabled,
                "vlan_id": binding.vlan_id,
                "fallback_vlan_id": binding.fallback_vlan_id,
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.patch("/sites/{site_id}/roles/{role_id}/platform-state")
    def set_site_binding_platform_state(
        site_id: str,
        role_id: str,
        payload: SwitchStateRequest,
        admin: db.Admin = Depends(deps.require_super_admin),
    ):
        session: Session = deps.get_db_session()
        try:
            binding = np.set_site_binding_platform_state(
                admin, site_id, role_id, payload.enabled, payload.reason, session
            )
            session.commit()
            return {
                "site_id": binding.site_id,
                "subsidiary_id": binding.subsidiary_id,
                "network_role_id": binding.network_role_id,
                "tenant_enabled": binding.tenant_enabled,
                "platform_enabled": binding.platform_enabled,
                "vlan_id": binding.vlan_id,
                "fallback_vlan_id": binding.fallback_vlan_id,
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.get("/sites/{site_id}/draft")
    def get_site_draft(
        site_id: str,
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session: Session = deps.get_db_session()
        try:
            site = session.get(db.Site, site_id)
            if not site:
                raise np.ResourceNotFoundError("Site not found")

            stmt = select(db.SiteRoleBinding).where(db.SiteRoleBinding.site_id == site_id)
            if admin.role != db.AdminRole.super_admin:
                actor_sub_id = np.resolve_admin_subsidiary_id(admin, session)
                if not actor_sub_id:
                    return {"site_id": site_id, "bindings": []}
                stmt = stmt.where(db.SiteRoleBinding.subsidiary_id == actor_sub_id)

            bindings = session.scalars(stmt).all()
            latest_rev = session.scalar(
                select(db.SitePolicyRevision.revision)
                .where(db.SitePolicyRevision.site_id == site_id)
                .order_by(db.SitePolicyRevision.revision.desc())
                .limit(1)
            ) or 0

            return {
                "site_id": site_id,
                "site_name": site.name,
                "current_revision": latest_rev,
                "bindings": [
                    {
                        "id": b.id,
                        "subsidiary_id": b.subsidiary_id,
                        "network_role_id": b.network_role_id,
                        "vlan_id": b.vlan_id,
                        "fallback_vlan_id": b.fallback_vlan_id,
                        "platform_enabled": b.platform_enabled,
                        "tenant_enabled": b.tenant_enabled,
                        "config_revision": b.config_revision,
                    }
                    for b in bindings
                ],
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.put("/sites/{site_id}/draft")
    def update_site_draft(
        site_id: str,
        payload: UpdateDraftRequest,
        admin: db.Admin = Depends(deps.require_super_admin),
    ):
        session: Session = deps.get_db_session()
        try:
            site = session.get(db.Site, site_id)
            if not site:
                raise np.ResourceNotFoundError("Site not found")

            updated_count = 0
            for item in payload.bindings:
                np.configure_site_role_binding(
                    actor=admin,
                    site_id=site_id,
                    subsidiary_id=item.subsidiary_id,
                    network_role_id=item.network_role_id,
                    vlan_id=item.vlan_id,
                    fallback_vlan_id=item.fallback_vlan_id,
                    session=session,
                    platform_enabled=item.platform_enabled,
                    tenant_enabled=item.tenant_enabled,
                )
                updated_count += 1

            session.commit()
            return {"updated_count": updated_count}
        except Exception as e:
            _handle_domain_error(e)

    @router.get("/sites/{site_id}/status")
    def get_site_policy_status(
        site_id: str,
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session: Session = deps.get_db_session()
        try:
            site = session.get(db.Site, site_id)
            if not site:
                raise np.ResourceNotFoundError("Site not found")

            latest_pub = session.scalar(
                select(db.SitePolicyRevision)
                .where(db.SitePolicyRevision.site_id == site_id)
                .order_by(db.SitePolicyRevision.revision.desc())
                .limit(1)
            )

            latest_ack = session.scalar(
                select(db.SitePolicyAck)
                .where(db.SitePolicyAck.site_id == site_id)
                .order_by(db.SitePolicyAck.installed_at.desc())
                .limit(1)
            )

            is_installed = (
                latest_pub is not None
                and latest_ack is not None
                and latest_ack.revision == latest_pub.revision
                and latest_ack.success
            )

            return {
                "site_id": site_id,
                "site_name": site.name,
                "published_revision": latest_pub.revision if latest_pub else 0,
                "published_at": latest_pub.issued_at.isoformat() if latest_pub else None,
                "installed_revision": latest_ack.revision if latest_ack else 0,
                "installed_at": latest_ack.installed_at.isoformat() if latest_ack else None,
                "distribution_status": "installed" if is_installed else "pending_distribution",
            }
        except Exception as e:
            _handle_domain_error(e)

    return router
