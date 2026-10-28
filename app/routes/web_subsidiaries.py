"""Super Admin UI for subsidiaries, departments, network roles, and which
sites a subsidiary is authorized to use (deploy/ADMIN-UI-SUBSIDIARIES-SPEC.md).

Before this, every subsidiary/department/role/site-binding in production
was created by hand-written one-off scripts against the database directly
-- the real service layer (app/network_policy.py) already existed and
already enforces every check below; this is just a form and a set of
tables over it, same house style as app/routes/web_sites.py.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from app import crl_health, db, network_policy as np
from app.routes import web_helpers as h


def get_router(deps, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["web-subsidiaries"])

    _crl_banner_context = crl_health.banner_context

    def _load_subsidiary_or_404(session, subsidiary_id: str) -> db.Subsidiary:
        sub = session.get(db.Subsidiary, subsidiary_id)
        if sub is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        return sub

    def _handle_policy_error(e: Exception):
        if isinstance(e, np.ForbiddenError):
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(e))
        if isinstance(e, np.ResourceNotFoundError):
            raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))
        if isinstance(e, np.ConflictError):
            raise HTTPException(status.HTTP_409_CONFLICT, str(e))
        if isinstance(e, np.PolicyValidationError):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
        raise

    @router.get("/subsidiaries")
    def subsidiaries_list(request: Request, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        subs = session.scalars(select(db.Subsidiary).order_by(db.Subsidiary.display_name)).all()
        rows = []
        for sub in subs:
            rows.append({
                "sub": sub,
                "department_count": len(session.scalars(
                    select(db.Department).where(db.Department.subsidiary_id == sub.id)
                ).all()),
                "role_count": len(session.scalars(
                    select(db.NetworkRole).where(db.NetworkRole.subsidiary_id == sub.id)
                ).all()),
            })
        return templates.TemplateResponse(
            request, "subsidiaries_list.html",
            {"admin": admin, "rows": rows, **_crl_banner_context(session)},
        )

    @router.post("/subsidiaries")
    def subsidiary_create(
        request: Request, code: str = Form(...), display_name: str = Form(...),
        admin: db.Admin = Depends(deps.require_super_admin),
    ):
        session = deps.get_db_session()
        try:
            np.create_subsidiary(admin, code, display_name, session)
            session.commit()
        except np.NetworkPolicyError as e:
            session.rollback()
            _handle_policy_error(e)
        return RedirectResponse(h.flash("/subsidiaries", f"Subsidiary '{display_name}' created.", "success"), status_code=303)

    @router.get("/subsidiaries/{subsidiary_id}")
    def subsidiary_detail(request: Request, subsidiary_id: str, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        sub = _load_subsidiary_or_404(session, subsidiary_id)

        departments = session.scalars(
            select(db.Department).where(db.Department.subsidiary_id == subsidiary_id).order_by(db.Department.display_name)
        ).all()
        roles = session.scalars(
            select(db.NetworkRole).where(db.NetworkRole.subsidiary_id == subsidiary_id).order_by(db.NetworkRole.display_name)
        ).all()
        dept_role_links = session.scalars(
            select(db.DepartmentRole).join(db.Department).where(db.Department.subsidiary_id == subsidiary_id)
        ).all()
        linked_pairs = {(link.department_id, link.network_role_id) for link in dept_role_links}

        all_sites = session.scalars(select(db.Site).order_by(db.Site.name)).all()
        site_auths = session.scalars(
            select(db.SiteSubsidiary).where(db.SiteSubsidiary.subsidiary_id == subsidiary_id)
        ).all()
        authorized_site_ids = {sa.site_id for sa in site_auths if sa.is_active}

        bindings = session.scalars(
            select(db.SiteRoleBinding).where(db.SiteRoleBinding.subsidiary_id == subsidiary_id)
        ).all()
        role_by_id = {r.id: r for r in roles}
        site_by_id = {s.id: s for s in all_sites}
        binding_rows = [
            {
                "binding": b,
                "role": role_by_id.get(b.network_role_id),
                "site": site_by_id.get(b.site_id),
            }
            for b in bindings
        ]

        return templates.TemplateResponse(
            request, "subsidiary_detail.html",
            {
                "admin": admin,
                "sub": sub,
                "departments": departments,
                "roles": roles,
                "linked_pairs": linked_pairs,
                "all_sites": all_sites,
                "authorized_site_ids": authorized_site_ids,
                "binding_rows": binding_rows,
                **_crl_banner_context(session),
            },
        )

    @router.post("/subsidiaries/{subsidiary_id}/departments")
    def department_create(
        request: Request, subsidiary_id: str, code: str = Form(...), display_name: str = Form(...),
        admin: db.Admin = Depends(deps.require_super_admin),
    ):
        session = deps.get_db_session()
        try:
            np.create_department(admin, subsidiary_id, code, display_name, session)
            session.commit()
        except np.NetworkPolicyError as e:
            session.rollback()
            _handle_policy_error(e)
        return RedirectResponse(h.flash(f"/subsidiaries/{subsidiary_id}", f"Department '{display_name}' created.", "success"), status_code=303)

    @router.post("/subsidiaries/{subsidiary_id}/roles")
    def role_create(
        request: Request, subsidiary_id: str, code: str = Form(...), display_name: str = Form(...),
        description: str = Form(""), is_privileged: str = Form(""),
        admin: db.Admin = Depends(deps.require_super_admin),
    ):
        session = deps.get_db_session()
        try:
            np.create_network_role(
                admin, subsidiary_id, code, display_name,
                description.strip() or None, is_privileged == "true", session,
            )
            session.commit()
        except np.NetworkPolicyError as e:
            session.rollback()
            _handle_policy_error(e)
        return RedirectResponse(h.flash(f"/subsidiaries/{subsidiary_id}", f"Network role '{display_name}' created.", "success"), status_code=303)

    @router.post("/subsidiaries/{subsidiary_id}/departments/{department_id}/link-role")
    def department_link_role(
        request: Request, subsidiary_id: str, department_id: str, role_id: str = Form(...),
        admin: db.Admin = Depends(deps.require_super_admin),
    ):
        session = deps.get_db_session()
        try:
            np.link_department_role(admin, department_id, role_id, session)
            session.commit()
        except np.NetworkPolicyError as e:
            session.rollback()
            _handle_policy_error(e)
        return RedirectResponse(h.flash(f"/subsidiaries/{subsidiary_id}", "Role linked to department.", "success"), status_code=303)

    @router.post("/subsidiaries/{subsidiary_id}/sites/{site_id}/authorize")
    def site_authorize(
        request: Request, subsidiary_id: str, site_id: str,
        admin: db.Admin = Depends(deps.require_super_admin),
    ):
        session = deps.get_db_session()
        try:
            np.authorize_site_subsidiary(admin, site_id, subsidiary_id, session)
            session.commit()
        except np.NetworkPolicyError as e:
            session.rollback()
            _handle_policy_error(e)
        return RedirectResponse(h.flash(f"/subsidiaries/{subsidiary_id}", "Site authorized for this subsidiary.", "success"), status_code=303)

    @router.post("/subsidiaries/{subsidiary_id}/sites/{site_id}/deauthorize")
    def site_deauthorize(
        request: Request, subsidiary_id: str, site_id: str,
        admin: db.Admin = Depends(deps.require_super_admin),
    ):
        session = deps.get_db_session()
        try:
            np.deauthorize_site_subsidiary(admin, site_id, subsidiary_id, session)
            session.commit()
        except np.NetworkPolicyError as e:
            session.rollback()
            _handle_policy_error(e)
        return RedirectResponse(h.flash(f"/subsidiaries/{subsidiary_id}", "Site deauthorized for this subsidiary — its bindings stop compiling into policy.json on the next publish.", "warn"), status_code=303)

    @router.post("/subsidiaries/{subsidiary_id}/bindings")
    def site_binding_configure(
        request: Request, subsidiary_id: str, site_id: str = Form(...),
        role_id: str = Form(...), vlan_id: int = Form(...), fallback_vlan_id: str = Form(""),
        admin: db.Admin = Depends(deps.require_super_admin),
    ):
        session = deps.get_db_session()
        fallback = int(fallback_vlan_id) if fallback_vlan_id.strip() else None
        try:
            np.configure_site_role_binding(
                admin, site_id, subsidiary_id, role_id,
                vlan_id=vlan_id, fallback_vlan_id=fallback, session=session,
            )
            session.commit()
        except np.NetworkPolicyError as e:
            session.rollback()
            _handle_policy_error(e)
        return RedirectResponse(h.flash(f"/subsidiaries/{subsidiary_id}", "Site VLAN binding configured.", "success"), status_code=303)

    return router
