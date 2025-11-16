# RBAC (Role-Based Access Control)

## Overview

**Role-Based Access Control (RBAC)** is an authorization model where permissions are assigned to roles, and users are assigned to roles. It's one of the most widely adopted access control models in enterprise systems.

## Key Concepts

### 1. Core Components

```
Users → Roles → Permissions → Resources
```

- **User**: An individual or service account
- **Role**: A collection of permissions (e.g., "Admin", "Editor", "Viewer")
- **Permission**: Allowed action on a resource (e.g., "read:document", "write:database")
- **Resource**: The object being accessed (e.g., file, API endpoint, database)

### 2. How RBAC Works

```
┌──────┐     assigned to    ┌──────┐     contains    ┌────────────┐     applied to    ┌──────────┐
│ User │ ──────────────────>│ Role │ ──────────────>│ Permission │ ──────────────────>│ Resource │
└──────┘                    └──────┘                └────────────┘                    └──────────┘
```

**Example:**
- Alice is assigned role "Editor"
- "Editor" role has permissions: ["read:articles", "write:articles", "delete:own-articles"]
- Alice can now read/write articles and delete her own articles

## RBAC Models

### Flat RBAC (RBAC0)
- Simple user-role-permission mapping
- No role hierarchies
- Most basic implementation

### Hierarchical RBAC (RBAC1)
- Roles can inherit permissions from other roles
- Example: "Admin" inherits all "Editor" permissions

```
Admin (senior role)
  ├── Editor permissions
  │     ├── Viewer permissions
  │     └── write:content
  └── delete:users (admin-only)
```

### Constrained RBAC (RBAC2)
- Adds constraints and separation of duties
- Mutual exclusion: User can't have both "Auditor" and "Finance Manager" roles
- Cardinality: Maximum N users can have "Admin" role

### Unified RBAC (RBAC3)
- Combines hierarchical and constrained RBAC
- Most comprehensive model

## Implementation Example

### Simple RBAC in JSON

```json
{
  "roles": {
    "admin": {
      "permissions": ["read:*", "write:*", "delete:*"]
    },
    "editor": {
      "permissions": ["read:articles", "write:articles", "delete:own-articles"]
    },
    "viewer": {
      "permissions": ["read:articles"]
    }
  },
  "users": {
    "alice@example.com": ["editor"],
    "bob@example.com": ["viewer"],
    "admin@example.com": ["admin"]
  }
}
```

### RBAC in Go

```go
package main

import "fmt"

type Permission string
type Role struct {
    Name        string
    Permissions []Permission
}

type User struct {
    Email string
    Roles []Role
}

func (u *User) HasPermission(perm Permission) bool {
    for _, role := range u.Roles {
        for _, p := range role.Permissions {
            if p == perm {
                return true
            }
        }
    }
    return false
}

func main() {
    editorRole := Role{
        Name: "Editor",
        Permissions: []Permission{"read:articles", "write:articles"},
    }

    alice := User{
        Email: "alice@example.com",
        Roles: []Role{editorRole},
    }

    fmt.Println(alice.HasPermission("write:articles")) // true
    fmt.Println(alice.HasPermission("delete:users"))   // false
}
```

## Advantages

✅ **Simplicity**: Easy to understand and implement
✅ **Scalability**: Add new roles without modifying code
✅ **Compliance**: Meets regulatory requirements (SOX, HIPAA)
✅ **Maintenance**: Centralized permission management
✅ **Audit**: Clear audit trails of role assignments

## Disadvantages

❌ **Role Explosion**: Too many fine-grained roles become unmanageable
❌ **Inflexibility**: Hard to handle exceptions and temporary access
❌ **Context-Blind**: Doesn't consider environmental factors (time, location)
❌ **Overprivileged**: Users may get unnecessary permissions through roles

## Use Cases

### Best For:
- Enterprise applications
- Organizations with clear hierarchies
- Systems with stable permission requirements
- Compliance-heavy industries

### Examples:
- Employee management systems
- Content management systems
- Banking applications
- Healthcare records systems

## RBAC vs Other Models

| Feature | RBAC | ABAC | ReBAC |
|---------|------|------|-------|
| Complexity | Low | High | Medium |
| Flexibility | Medium | High | High |
| Context-Aware | No | Yes | No |
| Relationship-Aware | No | No | Yes |
| Setup Time | Fast | Slow | Medium |

## Best Practices

1. **Principle of Least Privilege**: Give minimum necessary permissions
2. **Regular Audits**: Review role assignments quarterly
3. **Role Naming**: Use clear, descriptive names (avoid "Role1", "Role2")
4. **Document Roles**: Maintain clear documentation of what each role can do
5. **Avoid Role Explosion**: Limit number of roles (typically < 50 for most orgs)
6. **Separation of Duties**: Prevent conflict of interest with constraints
7. **Time-Bound Roles**: Implement temporary role assignments when needed

## Common Patterns

### 1. Role Inheritance
```yaml
roles:
  super_admin:
    inherits: [admin]
    permissions:
      - manage:roles
  admin:
    inherits: [editor]
    permissions:
      - delete:users
  editor:
    inherits: [viewer]
    permissions:
      - write:content
  viewer:
    permissions:
      - read:content
```

### 2. Multi-Tenancy RBAC
```
User: alice@company-a.com
Tenant: Company A
Role: Admin (scoped to Company A)
→ Can only administer Company A resources
```

### 3. Dynamic Role Assignment
- Role assigned based on attributes
- Example: All users with `department=engineering` get `developer` role

## Standards and Specifications

- **NIST RBAC**: Standard model defined by NIST
- **ANSI INCITS 359-2004**: American National Standard for RBAC
- **XACML**: XML-based access control markup language (supports RBAC)

## Tools Implementing RBAC

- **Casbin**: Supports RBAC with inheritance
- **Keycloak**: Built-in RBAC for IAM
- **AWS IAM**: Role-based permissions
- **Kubernetes RBAC**: Native cluster authorization
- **PostgreSQL**: Row-level security with roles

## Further Reading

- [NIST RBAC Model](https://csrc.nist.gov/projects/role-based-access-control)
- [RBAC on Wikipedia](https://en.wikipedia.org/wiki/Role-based_access_control)
- [AWS IAM Roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html)
- [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

## Next Steps

- Learn about [ABAC](./abac.md) for attribute-based access control
- Explore [ReBAC](./rebac.md) for relationship-based models
- See [Policy Making Techniques](../policy-standards/policy-making.md)
