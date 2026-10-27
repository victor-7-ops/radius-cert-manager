"""Network policy domain logic, permissions, role grants, switch toggles, and binding resolution.

Implements B02 and B08 specifications:
- Scoped permissions: platform superadmin, subsidiary superadmin, ordinary admin, viewer
- Assignment validation (subsidiary, department, role eligibility, admin grants)
- Normal VLAN vs explicitly configured fallback VLAN vs reject decision tree
- Role state switches (tenant-wide switch ON/OFF, site tenant switch ON/OFF, platform ceiling)
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import db
from app.network_migrations import resolve_subsidiary_alias

logger = logging.getLogger(__name__)


class NetworkPolicyError(Exception):
    """Base exception for network policy domain errors."""
    pass


class PolicyValidationError(NetworkPolicyError):
    """Validation failure (invalid input, mismatched tenant, bad VLAN, etc.) - maps to 422."""
    pass


class ForbiddenError(NetworkPolicyError):
    """Unauthorized action or missing grant/scope - maps to 403."""
    pass


class ResourceNotFoundError(NetworkPolicyError):
    """Referenced resource was not found or is out-of-scope - maps to 404."""
    pass


class ConflictError(NetworkPolicyError):
    """State conflict, optimistic concurrency revision mismatch, etc. - maps to 409."""
    pass


ConcurrencyError = ConflictError


@dataclass(frozen=True)
class BindingDecision:
    outcome: Literal["primary", "fallback", "reject"]
    vlan_id: int | None
    reason: str
    site_id: str
    subsidiary_id: str
    network_role_id: str


def resolve_admin_subsidiary_id(admin: db.Admin, session: Session) -> str | None:
    """Resolves an administrator's configured subsidiary scope to a canonical Subsidiary UUID.
    
    Returns None if unscoped (allowed for platform super_admin or unscoped ordinary admin).
    Returns None if the configured scope cannot be resolved to any approved active subsidiary.
    """
    scope = admin.subsidiary_scope
    if not scope:
        return None
    scope_str = scope.strip()
    
    # 1. Match by primary UUID
    sub = session.get(db.Subsidiary, scope_str)
    if sub is not None:
        return sub.id
    
    # 2. Match by exact code
    sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == scope_str))
    if sub is not None:
        return sub.id

    # 3. Match by exact display_name
    sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.display_name == scope_str))
    if sub is not None:
        return sub.id

    # 4. Match via legacy alias mapping
    canon_code = resolve_subsidiary_alias(scope_str)
    if canon_code:
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == canon_code))
        if sub is not None:
            return sub.id

    return None


def is_admin_in_scope(admin: db.Admin, subsidiary_id: str, session: Session) -> bool:
    """Checks whether an administrator is allowed to view/operate on a given subsidiary."""
    if admin.role == db.AdminRole.super_admin and not admin.subsidiary_scope:
        return True  # Unscoped platform superadmin can access all subsidiaries
    
    admin_sub_id = resolve_admin_subsidiary_id(admin, session)
    if not admin_sub_id:
        return False
    return admin_sub_id == subsidiary_id


def assert_can_manage_subsidiary(actor: db.Admin, subsidiary_id: str, session: Session) -> None:
    """Verifies that an actor has administrative authority over a specific subsidiary.
    
    Platform superadmins can manage any subsidiary (or their scoped one if scoped).
    Subsidiary superadmins can only manage their own approved subsidiary.
    Viewers and ordinary admins cannot manage subsidiary settings or roles.
    """
    if actor.role == db.AdminRole.viewer:
        raise ForbiddenError("Viewers have read-only access and cannot modify network settings")

    if actor.role == db.AdminRole.admin:
        raise ForbiddenError("Ordinary administrators cannot modify tenant network roles or settings")

    if actor.role == db.AdminRole.subsidiary_super_admin:
        actor_sub_id = resolve_admin_subsidiary_id(actor, session)
        if not actor_sub_id:
            raise ForbiddenError("Subsidiary superadmin requires an approved, valid subsidiary scope")
        if actor_sub_id != subsidiary_id:
            raise ForbiddenError("Subsidiary superadmin cannot manage resources of another subsidiary")
        return

    if actor.role == db.AdminRole.super_admin:
        if actor.subsidiary_scope:
            actor_sub_id = resolve_admin_subsidiary_id(actor, session)
            if actor_sub_id != subsidiary_id:
                raise ForbiddenError("Scoped superadmin cannot manage resources outside their assigned subsidiary")
        return

    raise ForbiddenError("Unauthorized role")


def create_subsidiary(
    actor: db.Admin, code: str, display_name: str, session: Session
) -> db.Subsidiary:
    if actor.role != db.AdminRole.super_admin:
        raise ForbiddenError("Only platform superadmins can create new subsidiaries")

    code_clean = code.strip().lower()
    if not code_clean:
        raise PolicyValidationError("Subsidiary code cannot be blank")

    existing = session.scalar(
        select(db.Subsidiary).where(db.Subsidiary.code == code_clean)
    )
    if existing:
        raise ConflictError(f"Subsidiary code '{code_clean}' already exists")

    sub = db.Subsidiary(
        code=code_clean,
        display_name=display_name.strip(),
        is_active=True,
    )
    session.add(sub)
    session.flush()
    db.audit(
        session,
        actor=actor.username,
        action="subsidiary.create",
        target=sub.code,
        detail=f"Created subsidiary {sub.display_name} ({sub.code})",
    )
    return sub


def create_department(
    actor: db.Admin, subsidiary_id: str, code: str, display_name: str, session: Session
) -> db.Department:
    assert_can_manage_subsidiary(actor, subsidiary_id, session)
    
    sub = session.get(db.Subsidiary, subsidiary_id)
    if not sub or not sub.is_active:
        raise PolicyValidationError("Target subsidiary does not exist or is inactive")

    code_clean = code.strip().lower()
    if not code_clean:
        raise PolicyValidationError("Department code cannot be blank")

    existing = session.scalar(
        select(db.Department).where(
            db.Department.subsidiary_id == subsidiary_id,
            db.Department.code == code_clean,
        )
    )
    if existing:
        raise ConflictError(f"Department code '{code_clean}' already exists in this subsidiary")

    dept = db.Department(
        subsidiary_id=subsidiary_id,
        code=code_clean,
        display_name=display_name.strip(),
        is_active=True,
    )
    session.add(dept)
    session.flush()
    db.audit(
        session,
        actor=actor.username,
        action="department.create",
        target=dept.code,
        detail=f"Created department {dept.display_name} ({dept.id})",
        subsidiary=sub.display_name,
    )
    return dept


def create_network_role(
    actor: db.Admin,
    subsidiary_id: str,
    code: str,
    display_name: str,
    description: str | None,
    is_privileged: bool,
    session: Session,
) -> db.NetworkRole:
    assert_can_manage_subsidiary(actor, subsidiary_id, session)

    sub = session.get(db.Subsidiary, subsidiary_id)
    if not sub or not sub.is_active:
        raise PolicyValidationError("Target subsidiary does not exist or is inactive")

    code_clean = code.strip().lower()
    if not code_clean:
        raise PolicyValidationError("Network role code cannot be blank")

    existing = session.scalar(
        select(db.NetworkRole).where(
            db.NetworkRole.subsidiary_id == subsidiary_id,
            db.NetworkRole.code == code_clean,
        )
    )
    if existing:
        raise ConflictError(f"Network role code '{code_clean}' already exists in this subsidiary")

    role = db.NetworkRole(
        subsidiary_id=subsidiary_id,
        code=code_clean,
        display_name=display_name.strip(),
        description=description.strip() if description else None,
        is_active=True,
        is_privileged=is_privileged,
    )
    session.add(role)
    session.flush()
    db.audit(
        session,
        actor=actor.username,
        action="network_role.create",
        target=role.code,
        detail=f"Created network role {role.display_name} ({role.id}) privileged={is_privileged}",
        subsidiary=sub.display_name,
    )
    return role


def link_department_role(
    actor: db.Admin, department_id: str, role_id: str, session: Session
) -> db.DepartmentRole:
    dept = session.get(db.Department, department_id)
    if not dept:
        raise ResourceNotFoundError("Department not found")

    role = session.get(db.NetworkRole, role_id)
    if not role:
        raise ResourceNotFoundError("Network role not found")

    if dept.subsidiary_id != role.subsidiary_id:
        raise PolicyValidationError("Cross-subsidiary department and network role linking is forbidden")

    assert_can_manage_subsidiary(actor, dept.subsidiary_id, session)

    existing = session.scalar(
        select(db.DepartmentRole).where(
            db.DepartmentRole.department_id == department_id,
            db.DepartmentRole.network_role_id == role_id,
        )
    )
    if existing:
        return existing

    dep_role = db.DepartmentRole(department_id=department_id, network_role_id=role_id)
    session.add(dep_role)
    session.flush()
    db.audit(
        session,
        actor=actor.username,
        action="department_role.link",
        target=f"{dept.code}:{role.code}",
        detail=f"Linked department {dept.display_name} to role {role.display_name}",
        subsidiary=dept.subsidiary.display_name if dept.subsidiary else None,
    )
    return dep_role


def grant_role(
    actor: db.Admin, target_admin_id: str, role_id: str, session: Session
) -> db.AdminRoleGrant:
    """Grants issuance permission for a specific network role to an ordinary administrator."""
    role = session.get(db.NetworkRole, role_id)
    if not role:
        raise ResourceNotFoundError("Network role not found")

    assert_can_manage_subsidiary(actor, role.subsidiary_id, session)

    target_admin = session.get(db.Admin, target_admin_id)
    if not target_admin:
        raise ResourceNotFoundError("Target administrator not found")

    if target_admin.subsidiary_scope:
        target_sub_id = resolve_admin_subsidiary_id(target_admin, session)
        if target_sub_id != role.subsidiary_id:
            raise PolicyValidationError(
                "Cannot grant network role from a different subsidiary to a scoped administrator"
            )

    existing = session.scalar(
        select(db.AdminRoleGrant).where(
            db.AdminRoleGrant.admin_id == target_admin_id,
            db.AdminRoleGrant.network_role_id == role_id,
        )
    )
    if existing:
        return existing

    grant = db.AdminRoleGrant(
        admin_id=target_admin_id,
        network_role_id=role_id,
        granted_by=actor.username,
    )
    session.add(grant)
    session.flush()
    db.audit(
        session,
        actor=actor.username,
        action="admin.grant_role",
        target=target_admin.username,
        detail=f"Granted network role {role.code} ({role.id})",
        subsidiary=role.subsidiary.display_name if role.subsidiary else None,
    )
    return grant


def revoke_grant(
    actor: db.Admin, target_admin_id: str, role_id: str, session: Session
) -> None:
    role = session.get(db.NetworkRole, role_id)
    if not role:
        raise ResourceNotFoundError("Network role not found")

    assert_can_manage_subsidiary(actor, role.subsidiary_id, session)

    target_admin = session.get(db.Admin, target_admin_id)
    if not target_admin:
        raise ResourceNotFoundError("Target administrator not found")

    grant = session.scalar(
        select(db.AdminRoleGrant).where(
            db.AdminRoleGrant.admin_id == target_admin_id,
            db.AdminRoleGrant.network_role_id == role_id,
        )
    )
    if grant:
        session.delete(grant)
        session.flush()
        db.audit(
            session,
            actor=actor.username,
            action="admin.revoke_role_grant",
            target=target_admin.username,
            detail=f"Revoked network role grant for {role.code}",
            subsidiary=role.subsidiary.display_name if role.subsidiary else None,
        )


def validate_assignment(
    actor: db.Admin,
    subsidiary_id: str,
    department_id: str,
    role_id: str,
    session: Session,
) -> None:
    """Validates that an actor has permission to issue/assign a device to a department and network role.
    
    Verifies:
    1. Actor write permission (not viewer) and tenant scope match.
    2. Ordinary admins have explicit AdminRoleGrant for the network role.
    3. Target subsidiary exists and is active.
    4. Target department exists, belongs to subsidiary, and is active.
    5. Target role exists, belongs to subsidiary, and is active (tenant-wide switch is ON).
    6. Target department is eligible for the network role (DepartmentRole link exists).
    7. At least one site role binding exists for this subsidiary and network role.
    """
    if actor.role == db.AdminRole.viewer:
        raise ForbiddenError("Read-only viewer cannot assign or issue network identities")

    if not is_admin_in_scope(actor, subsidiary_id, session):
        raise ForbiddenError("Actor is not authorized for this subsidiary")

    # Ordinary admin requires explicit issuance grant
    if actor.role == db.AdminRole.admin:
        has_grant = session.scalar(
            select(db.AdminRoleGrant).where(
                db.AdminRoleGrant.admin_id == actor.id,
                db.AdminRoleGrant.network_role_id == role_id,
            )
        )
        if not has_grant:
            raise ForbiddenError(f"Admin '{actor.username}' has not been granted network role {role_id}")

    sub = session.get(db.Subsidiary, subsidiary_id)
    if not sub or not sub.is_active:
        raise PolicyValidationError("Subsidiary is inactive or nonexistent")

    dept = session.get(db.Department, department_id)
    if not dept or not dept.is_active or dept.subsidiary_id != subsidiary_id:
        raise PolicyValidationError("Department does not belong to subsidiary or is inactive")

    role = session.get(db.NetworkRole, role_id)
    if not role or not role.is_active or role.subsidiary_id != subsidiary_id:
        raise PolicyValidationError("Network role does not belong to subsidiary or is inactive")

    # Verify department-role eligibility
    dep_role = session.scalar(
        select(db.DepartmentRole).where(
            db.DepartmentRole.department_id == department_id,
            db.DepartmentRole.network_role_id == role_id,
        )
    )
    if not dep_role:
        raise PolicyValidationError(
            f"Department '{dept.display_name}' is not authorized for network role '{role.display_name}'"
        )

    # Verify at least one site binding exists for this role
    has_binding = session.scalar(
        select(db.SiteRoleBinding).where(
            db.SiteRoleBinding.subsidiary_id == subsidiary_id,
            db.SiteRoleBinding.network_role_id == role_id,
        )
    )
    if not has_binding:
        raise PolicyValidationError(
            f"Network role '{role.display_name}' has no active site bindings configured"
        )


def resolve_binding(
    site_id: str,
    subsidiary_id: str,
    role_id: str,
    session: Session,
) -> BindingDecision:
    """Evaluates the local site policy for an incoming authentication request.
    
    Decision rules (SUBSIDIARY-SUPERADMIN.md §30-55):
    - Platform disabled -> REJECT (never fallback)
    - Inactive subsidiary -> REJECT (never fallback)
    - Site subsidiary restricted & not allowed -> REJECT
    - No binding -> REJECT
    - If tenant-wide switch (NetworkRole.is_active) AND site switch (SiteRoleBinding.tenant_enabled) are ON:
        -> PRIMARY VLAN
    - If either tenant switch is OFF:
        -> Explicitly configured FALLBACK VLAN (if valid and configured)
        -> REJECT if fallback VLAN is missing, invalid, or equals primary VLAN
    """
    sub = session.get(db.Subsidiary, subsidiary_id)
    if not sub or not sub.is_active:
        return BindingDecision(
            outcome="reject",
            vlan_id=None,
            reason="Subsidiary nonexistent or inactive",
            site_id=site_id,
            subsidiary_id=subsidiary_id,
            network_role_id=role_id,
        )

    # Check site-subsidiary restriction if configured
    site_subs = session.scalars(
        select(db.SiteSubsidiary).where(db.SiteSubsidiary.site_id == site_id)
    ).all()
    if site_subs:
        allowed_subs = {ss.subsidiary_id for ss in site_subs if ss.is_active}
        if subsidiary_id not in allowed_subs:
            return BindingDecision(
                outcome="reject",
                vlan_id=None,
                reason="Subsidiary not authorized at this site",
                site_id=site_id,
                subsidiary_id=subsidiary_id,
                network_role_id=role_id,
            )

    role = session.get(db.NetworkRole, role_id)
    if not role or role.subsidiary_id != subsidiary_id:
        return BindingDecision(
            outcome="reject",
            vlan_id=None,
            reason="Network role not found or belongs to another subsidiary",
            site_id=site_id,
            subsidiary_id=subsidiary_id,
            network_role_id=role_id,
        )

    binding = session.scalar(
        select(db.SiteRoleBinding).where(
            db.SiteRoleBinding.site_id == site_id,
            db.SiteRoleBinding.subsidiary_id == subsidiary_id,
            db.SiteRoleBinding.network_role_id == role_id,
        )
    )
    if not binding:
        return BindingDecision(
            outcome="reject",
            vlan_id=None,
            reason="No VLAN binding configured for this site, subsidiary, and network role",
            site_id=site_id,
            subsidiary_id=subsidiary_id,
            network_role_id=role_id,
        )

    # Platform block check - platform block always rejects, NEVER falls back
    if not binding.platform_enabled:
        return BindingDecision(
            outcome="reject",
            vlan_id=None,
            reason="Platform administration has disabled this site role binding",
            site_id=site_id,
            subsidiary_id=subsidiary_id,
            network_role_id=role_id,
        )

    # Evaluate tenant switches
    tenant_role_on = role.is_active
    tenant_site_on = binding.tenant_enabled

    if tenant_role_on and tenant_site_on:
        return BindingDecision(
            outcome="primary",
            vlan_id=binding.vlan_id,
            reason="Active role and site binding: assigned primary VLAN",
            site_id=site_id,
            subsidiary_id=subsidiary_id,
            network_role_id=role_id,
        )

    # Tenant switch is OFF: evaluate fallback VLAN
    fallback_vlan = binding.fallback_vlan_id
    if (
        fallback_vlan is None
        or not (1 <= fallback_vlan <= 4094)
        or fallback_vlan == binding.vlan_id
    ):
        return BindingDecision(
            outcome="reject",
            vlan_id=None,
            reason="Tenant switch is OFF but no valid approved fallback VLAN is configured",
            site_id=site_id,
            subsidiary_id=subsidiary_id,
            network_role_id=role_id,
        )

    switch_reason = "tenant role switch OFF" if not tenant_role_on else "site tenant switch OFF"
    return BindingDecision(
        outcome="fallback",
        vlan_id=fallback_vlan,
        reason=f"{switch_reason}: assigned configured fallback VLAN",
        site_id=site_id,
        subsidiary_id=subsidiary_id,
        network_role_id=role_id,
    )


def configure_site_role_binding(
    actor: db.Admin,
    site_id: str,
    subsidiary_id: str,
    role_id: str | None = None,
    vlan_id: int = 1,
    fallback_vlan_id: int | None = None,
    session: Session | None = None,
    network_role_id: str | None = None,
    platform_enabled: bool | None = None,
    tenant_enabled: bool | None = None,
) -> db.SiteRoleBinding:
    """Configures the infrastructure VLAN and fallback VLAN for a site role binding.
    
    Only platform superadmins can configure VLAN numbers (SUBSIDIARY-SUPERADMIN.md §17).
    """
    if actor.role != db.AdminRole.super_admin:
        raise ForbiddenError("Only platform superadmins can configure site VLAN infrastructure")

    if session is None:
        raise PolicyValidationError("Database session is required")

    effective_role_id = role_id or network_role_id
    if not effective_role_id:
        raise PolicyValidationError("Network role ID is required")

    if not (1 <= vlan_id <= 4094):
        raise PolicyValidationError(f"Primary VLAN ID {vlan_id} must be between 1 and 4094")

    if fallback_vlan_id is not None:
        if not (1 <= fallback_vlan_id <= 4094):
            raise PolicyValidationError(f"Fallback VLAN ID {fallback_vlan_id} must be between 1 and 4094")
        if fallback_vlan_id == vlan_id:
            raise PolicyValidationError("Fallback VLAN cannot be identical to primary VLAN")

    site = session.get(db.Site, site_id)
    if not site:
        raise ResourceNotFoundError("Site not found")

    role = session.get(db.NetworkRole, effective_role_id)
    if not role or role.subsidiary_id != subsidiary_id:
        raise ResourceNotFoundError("Network role not found in this subsidiary")

    binding = session.scalar(
        select(db.SiteRoleBinding).where(
            db.SiteRoleBinding.site_id == site_id,
            db.SiteRoleBinding.subsidiary_id == subsidiary_id,
            db.SiteRoleBinding.network_role_id == effective_role_id,
        )
    )
    if binding:
        binding.vlan_id = vlan_id
        binding.fallback_vlan_id = fallback_vlan_id
        if platform_enabled is not None:
            binding.platform_enabled = platform_enabled
        if tenant_enabled is not None:
            binding.tenant_enabled = tenant_enabled
        binding.config_revision += 1
    else:
        binding = db.SiteRoleBinding(
            site_id=site_id,
            subsidiary_id=subsidiary_id,
            network_role_id=effective_role_id,
            vlan_id=vlan_id,
            fallback_vlan_id=fallback_vlan_id,
            platform_enabled=platform_enabled if platform_enabled is not None else True,
            tenant_enabled=tenant_enabled if tenant_enabled is not None else True,
            config_revision=1,
        )
        session.add(binding)

    session.flush()
    db.audit(
        session,
        actor=actor.username,
        action="site_binding.configure",
        target=f"{site.name}:{role.code}",
        detail=f"Configured binding VLAN {vlan_id} fallback {fallback_vlan_id} rev {binding.config_revision}",
        subsidiary=role.subsidiary.display_name if role.subsidiary else None,
        site_id=site.id,
    )
    return binding


def set_network_role_tenant_state(
    actor: db.Admin,
    role_id: str,
    is_active: bool,
    reason: str,
    session: Session,
) -> db.NetworkRole:
    """Toggles tenant-wide network role state ON/OFF."""
    role = session.get(db.NetworkRole, role_id)
    if not role:
        raise ResourceNotFoundError("Network role not found")

    assert_can_manage_subsidiary(actor, role.subsidiary_id, session)

    if not reason or not reason.strip():
        raise PolicyValidationError("Reason is required for changing network role state")

    role.is_active = is_active
    session.flush()
    db.audit(
        session,
        actor=actor.username,
        action="network_role.state_change",
        target=role.code,
        detail=f"Set role state to {'ON' if is_active else 'OFF'}: {reason.strip()}",
        subsidiary=role.subsidiary.display_name if role.subsidiary else None,
    )
    return role


def set_site_binding_tenant_state(
    actor: db.Admin,
    site_id: str,
    role_id: str,
    tenant_enabled: bool,
    reason: str,
    session: Session,
) -> db.SiteRoleBinding:
    """Toggles tenant switch for a selected site binding ON/OFF."""
    role = session.get(db.NetworkRole, role_id)
    if not role:
        raise ResourceNotFoundError("Network role not found")

    assert_can_manage_subsidiary(actor, role.subsidiary_id, session)

    if not reason or not reason.strip():
        raise PolicyValidationError("Reason is required for changing tenant site binding state")

    binding = session.scalar(
        select(db.SiteRoleBinding).where(
            db.SiteRoleBinding.site_id == site_id,
            db.SiteRoleBinding.network_role_id == role_id,
        )
    )
    if not binding:
        raise ResourceNotFoundError("Site role binding not found")

    # If setting OFF, ensure fallback VLAN is configured
    if not tenant_enabled and not binding.fallback_vlan_id:
        raise PolicyValidationError(
            "Cannot switch site role binding OFF: no fallback VLAN is configured for this binding"
        )

    binding.tenant_enabled = tenant_enabled
    binding.config_revision += 1
    session.flush()
    db.audit(
        session,
        actor=actor.username,
        action="site_binding.tenant_state_change",
        target=f"{site_id}:{role.code}",
        detail=f"Set tenant switch to {'ON' if tenant_enabled else 'OFF'}: {reason.strip()}",
        subsidiary=role.subsidiary.display_name if role.subsidiary else None,
        site_id=site_id,
    )
    return binding


def set_site_binding_platform_state(
    actor: db.Admin,
    site_id: str,
    role_id: str,
    platform_enabled: bool,
    reason: str,
    session: Session,
) -> db.SiteRoleBinding:
    """Toggles platform ceiling for a site binding. Only platform superadmin can call this."""
    if actor.role != db.AdminRole.super_admin:
        raise ForbiddenError("Only platform superadmins can toggle platform binding ceiling")

    if not reason or not reason.strip():
        raise PolicyValidationError("Reason is required for changing platform binding ceiling")

    binding = session.scalar(
        select(db.SiteRoleBinding).where(
            db.SiteRoleBinding.site_id == site_id,
            db.SiteRoleBinding.network_role_id == role_id,
        )
    )
    if not binding:
        raise ResourceNotFoundError("Site role binding not found")

    binding.platform_enabled = platform_enabled
    binding.config_revision += 1
    session.flush()
    db.audit(
        session,
        actor=actor.username,
        action="site_binding.platform_state_change",
        target=f"{site_id}:{role_id}",
        detail=f"Set platform ceiling to {'ENABLED' if platform_enabled else 'DISABLED'}: {reason.strip()}",
        site_id=site_id,
    )
    return binding
