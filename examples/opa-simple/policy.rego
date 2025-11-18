package authz

# Default deny - if no rule explicitly allows, deny access
default allow = false

# Rule 1: Admins can perform any action on any resource
allow {
    user_has_role(input.user, "admin")
}

# Rule 2: Editors can read and write their own resources
allow {
    user_has_role(input.user, "editor")
    input.action in ["read", "write"]
    resource_owner(input.resource, input.user)
}

# Rule 3: Editors can read any resource (but only write their own)
allow {
    user_has_role(input.user, "editor")
    input.action == "read"
}

# Rule 4: Viewers can read any resource
allow {
    user_has_role(input.user, "viewer")
    input.action == "read"
}

# Rule 5: Resource owners can delete their own resources
allow {
    input.action == "delete"
    resource_owner(input.resource, input.user)
    user_has_role(input.user, "editor")
}

# Helper function: Check if user has a specific role
user_has_role(user, role) {
    data.users[user].roles[_] == role
}

# Helper function: Check if user owns the resource
resource_owner(resource, user) {
    data.resources[resource].owner == user
}

# Additional query: Get allowed actions for a user on a resource
allowed_actions[action] {
    actions := ["read", "write", "delete"]
    action := actions[_]
    allow with input as {"user": input.user, "resource": input.resource, "action": action}
}

# Query: Check if user can access resource (read at minimum)
can_access {
    allow with input.action as "read"
}
