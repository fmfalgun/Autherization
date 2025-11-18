package multitenant.authz

import future.keywords

# Default deny
default allow := false

# Superadmins can do anything
allow if {
    input.user.role == "superadmin"
}

# Users can access resources in their own tenant
allow if {
    input.user.tenant == input.resource.tenant
    has_permission(input.user.role, input.action)
}

# Parent tenant admins can access child tenant resources
allow if {
    input.user.role == "admin"
    is_parent_tenant(input.user.tenant, input.resource.tenant)
}

# Tenant admins can manage users in their tenant
allow if {
    input.action == "manage_users"
    input.user.role == "admin"
    input.user.tenant == input.target_tenant
}

# Helper: Check if user role has permission for action
has_permission(role, action) if {
    role == "admin"
}

has_permission(role, action) if {
    role == "user"
    action in ["read", "list"]
}

has_permission(role, action) if {
    role == "editor"
    action in ["read", "list", "create", "update"]
}

# Helper: Check if tenant1 is parent of tenant2
is_parent_tenant(parent, child) if {
    data.tenants[child].parent == parent
}

# Helper: Check if tenant1 is ancestor of tenant2 (recursive)
is_ancestor_tenant(ancestor, descendant) if {
    is_parent_tenant(ancestor, descendant)
}

is_ancestor_tenant(ancestor, descendant) if {
    parent := data.tenants[descendant].parent
    is_ancestor_tenant(ancestor, parent)
}

# Query: Get all accessible tenants for a user
accessible_tenants contains tenant_id if {
    tenant_id := input.user.tenant
}

accessible_tenants contains tenant_id if {
    input.user.role == "admin"
    tenant := data.tenants[tenant_id]
    is_parent_tenant(input.user.tenant, tenant_id)
}

accessible_tenants contains tenant_id if {
    input.user.role == "superadmin"
    tenant_id := data.tenants[_].id
}

# Query: Can user perform action on resource?
allowed_actions contains action if {
    actions := ["read", "create", "update", "delete", "list"]
    action := actions[_]
    allow with input.action as action
}
