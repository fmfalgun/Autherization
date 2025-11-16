# Policy Making Techniques and Best Practices

## Overview

Authorization policies define who can do what under which circumstances. Well-designed policies are clear, maintainable, auditable, and secure. This guide covers techniques for creating effective authorization policies.

## Policy Design Principles

### 1. Principle of Least Privilege (PoLP)

Grant minimum permissions necessary to perform a task.

**Bad**:
```yaml
role: developer
permissions:
  - read:*
  - write:*
  - delete:*  # Too broad!
```

**Good**:
```yaml
role: developer
permissions:
  - read:code
  - write:code
  - read:logs
  - write:test_environments
  # Only what's needed
```

### 2. Separation of Duties (SoD)

Prevent conflicts of interest by distributing critical functions among different people.

```yaml
policies:
  - name: no_approve_own_changes
    deny:
      - subject.id == resource.author
      - action == "approve"

  - name: separate_dev_and_audit
    mutual_exclusion:
      - roles: [developer, auditor]
```

### 3. Default Deny

Always start with deny, explicitly allow.

```rego
package authz

# Start with default deny
default allow = false

# Explicitly allow specific conditions
allow {
    input.user.role == "admin"
}
```

### 4. Explicit Over Implicit

Make policies clear and explicit, avoid assumptions.

**Bad** (Implicit):
```yaml
# Assumes developers can access production
developer:
  permissions: [deploy]
```

**Good** (Explicit):
```yaml
developer:
  permissions:
    - deploy:staging
    - deploy:development
# Production deployment requires separate approval
```

### 5. Defense in Depth

Layer multiple authorization checks.

```go
// Multiple layers of checks
if !authenticatedUser(request) {
    return unauthorized
}

if !authorizedRole(user, resource) {
    return forbidden
}

if !rateLimit(user) {
    return tooManyRequests
}

if !contextualCheck(user, resource, environment) {
    return forbidden
}

return allowed
```

## Policy Writing Techniques

### Technique 1: Role-Based Policies

Group permissions by role.

```yaml
roles:
  system_admin:
    description: Full system control
    inherits: []
    permissions:
      - system:*
      - users:*
      - audit:read

  security_admin:
    description: Security and compliance
    inherits: []
    permissions:
      - audit:*
      - security:*
      - users:read

  application_admin:
    description: Application management
    inherits: [viewer]
    permissions:
      - app:*
      - config:*
```

### Technique 2: Resource-Based Policies

Define access at resource level.

```yaml
resource: document
policies:
  - name: owner_full_access
    allow:
      - subject: resource.owner
      - actions: ["*"]

  - name: collaborator_edit
    allow:
      - subject: resource.collaborators
      - actions: [read, write]

  - name: public_read
    allow:
      - subject: "*"
      - actions: [read]
      - condition: resource.visibility == "public"
```

### Technique 3: Attribute-Based Policies

Use attributes for dynamic decisions.

```rego
package abac

allow {
    # User attributes
    input.user.department == "engineering"
    input.user.clearance_level >= 3

    # Resource attributes
    input.resource.classification <= input.user.clearance_level
    input.resource.owner_department == input.user.department

    # Environmental attributes
    is_business_hours
    is_corporate_network
}

is_business_hours {
    hour := time.clock(time.now_ns())[0]
    hour >= 9
    hour < 17
}

is_corporate_network {
    net.cidr_contains("10.0.0.0/8", input.environment.ip)
}
```

### Technique 4: Relationship-Based Policies

Model complex relationships.

```yaml
# SpiceDB schema
schema: |
  definition user {}

  definition organization {
    relation admin: user
    relation member: user

    permission view_billing = admin
    permission invite_users = admin
  }

  definition project {
    relation organization: organization
    relation owner: user
    relation contributor: user

    permission view = contributor + owner + organization->member
    permission edit = owner + organization->admin
    permission delete = owner + organization->admin
  }
```

### Technique 5: Temporal Policies

Time-based access control.

```rego
package temporal

# Time window access
allow {
    input.action == "access_sensitive_data"
    input.user.role == "analyst"
    within_allowed_hours
}

within_allowed_hours {
    now := time.now_ns()
    hour := time.clock(now)[0]

    # Monday-Friday, 9 AM - 5 PM
    day := time.weekday(now)
    day != "Saturday"
    day != "Sunday"
    hour >= 9
    hour < 17
}

# Expiring permissions
allow {
    input.user.temporary_access
    input.user.access_expires_at > time.now_ns()
}
```

## Policy Structure Patterns

### Pattern 1: Hierarchical Structure

```yaml
organization/
├── global_policies/
│   ├── authentication.rego
│   ├── rate_limiting.rego
│   └── audit.rego
├── department_policies/
│   ├── engineering/
│   │   ├── code_access.rego
│   │   └── deployment.rego
│   ├── finance/
│   │   ├── financial_data.rego
│   │   └── approval_workflows.rego
│   └── hr/
│       └── employee_data.rego
└── application_policies/
    ├── api_gateway.rego
    ├── database.rego
    └── storage.rego
```

### Pattern 2: Layered Policies

```rego
package layered_authz

# Layer 1: Authentication (must be authenticated)
authenticated {
    input.user.authenticated == true
}

# Layer 2: Basic authorization (role check)
has_basic_access {
    authenticated
    input.user.role in ["user", "admin", "moderator"]
}

# Layer 3: Resource-level authorization
has_resource_access {
    has_basic_access
    resource_owner
}

has_resource_access {
    has_basic_access
    resource_shared_with_user
}

# Layer 4: Contextual checks
allow {
    has_resource_access
    not suspicious_activity
    within_rate_limit
}

resource_owner {
    input.resource.owner == input.user.id
}

resource_shared_with_user {
    input.user.id in input.resource.shared_with
}
```

### Pattern 3: Modular Policies

```rego
# roles.rego
package authz.roles

admin {
    input.user.role == "admin"
}

editor {
    input.user.role == "editor"
    input.user.department == input.resource.department
}

# permissions.rego
package authz.permissions

can_delete {
    data.authz.roles.admin
}

can_edit {
    data.authz.roles.admin
}

can_edit {
    data.authz.roles.editor
}

can_read {
    data.authz.roles.admin
}

can_read {
    data.authz.roles.editor
}

# main.rego
package authz

import data.authz.permissions

allow {
    input.action == "delete"
    permissions.can_delete
}

allow {
    input.action == "edit"
    permissions.can_edit
}

allow {
    input.action == "read"
    permissions.can_read
}
```

## Policy Testing Strategies

### 1. Unit Testing

```rego
package authz_test

import data.authz

# Test positive case
test_admin_can_delete {
    authz.allow with input as {
        "user": {"role": "admin"},
        "action": "delete",
        "resource": {"id": "doc-123"}
    }
}

# Test negative case
test_viewer_cannot_delete {
    not authz.allow with input as {
        "user": {"role": "viewer"},
        "action": "delete",
        "resource": {"id": "doc-123"}
    }
}

# Test edge cases
test_no_role_denies_access {
    not authz.allow with input as {
        "user": {"id": "user-123"},  # No role
        "action": "read"
    }
}
```

### 2. Integration Testing

```yaml
# Test scenarios
scenarios:
  - name: admin_full_access
    user:
      id: alice
      role: admin
    tests:
      - action: read
        resource: any
        expected: allow
      - action: write
        resource: any
        expected: allow
      - action: delete
        resource: any
        expected: allow

  - name: editor_limited_access
    user:
      id: bob
      role: editor
      department: engineering
    tests:
      - action: read
        resource: {department: engineering}
        expected: allow
      - action: write
        resource: {department: engineering}
        expected: allow
      - action: delete
        resource: {department: engineering}
        expected: deny
      - action: write
        resource: {department: finance}
        expected: deny
```

### 3. Property-Based Testing

```go
func TestPolicyProperties(t *testing.T) {
    // Property: Admins can always access
    t.Run("admins_always_allowed", func(t *testing.T) {
        for i := 0; i < 100; i++ {
            input := generateRandomInput()
            input["user"].(map[string]interface{})["role"] = "admin"

            result := evaluate(input)
            if !result {
                t.Errorf("Admin should always be allowed")
            }
        }
    })

    // Property: Default deny
    t.Run("default_deny_without_role", func(t *testing.T) {
        for i := 0; i < 100; i++ {
            input := generateRandomInput()
            delete(input["user"].(map[string]interface{}), "role")

            result := evaluate(input)
            if result {
                t.Errorf("Should deny without role")
            }
        }
    })
}
```

## Policy Versioning

```yaml
# Version 1.0.0
apiVersion: policy/v1
kind: AuthorizationPolicy
metadata:
  name: document_access
  version: 1.0.0
  deprecated: false
spec:
  allow:
    - subject: owner
      actions: ["*"]

---
# Version 2.0.0 (breaking change)
apiVersion: policy/v2
kind: AuthorizationPolicy
metadata:
  name: document_access
  version: 2.0.0
  deprecated: false
  breaking_changes:
    - "Removed wildcard permissions"
    - "Added explicit action list"
spec:
  allow:
    - subject: owner
      actions: [read, write, delete, share]  # Explicit
```

## Policy Review Checklist

- [ ] **Security**
  - [ ] Default deny implemented
  - [ ] No overly permissive rules
  - [ ] Sensitive actions require MFA
  - [ ] Separation of duties enforced

- [ ] **Clarity**
  - [ ] Clear naming conventions
  - [ ] Documented with comments
  - [ ] No ambiguous conditions

- [ ] **Performance**
  - [ ] No expensive operations
  - [ ] Indexed data lookups
  - [ ] Cached when possible

- [ ] **Testability**
  - [ ] Unit tests exist
  - [ ] Integration tests pass
  - [ ] Edge cases covered

- [ ] **Maintainability**
  - [ ] Modular structure
  - [ ] Versioned
  - [ ] Change log updated

- [ ] **Compliance**
  - [ ] Meets regulatory requirements
  - [ ] Audit logging enabled
  - [ ] Data retention policies

## Common Anti-Patterns

### ❌ Over-Permissive Defaults

```rego
# BAD: Default allow
default allow = true

# GOOD: Default deny
default allow = false
```

### ❌ Hard-Coded Values

```rego
# BAD: Hard-coded
allow {
    input.user.id == "alice@example.com"
}

# GOOD: Data-driven
allow {
    input.user.id in data.admin_users
}
```

### ❌ Complex Nested Logic

```rego
# BAD: Hard to understand
allow {
    (input.user.role == "admin" || (input.user.role == "editor" && input.resource.owner == input.user.id)) && (input.action == "read" || (input.action == "write" && input.time < input.resource.deadline))
}

# GOOD: Broken down
allow {
    is_authorized_user
    is_allowed_action
}

is_authorized_user {
    input.user.role == "admin"
}

is_authorized_user {
    input.user.role == "editor"
    input.resource.owner == input.user.id
}
```

## Further Reading

- [NIST ABAC Guide](https://csrc.nist.gov/publications/detail/sp/800-162/final)
- [OPA Policy Best Practices](https://www.openpolicyagent.org/docs/latest/policy-performance/)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

## Next Steps

- Review [Industry Standards](./standards.md)
- Learn [Rego](../technologies/rego.md) for policy implementation
- Understand [ABAC](../concepts/abac.md) for attribute-based policies
- Explore [OPA Framework](../../frameworks/opa/)
