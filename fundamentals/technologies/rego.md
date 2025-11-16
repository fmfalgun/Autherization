# Rego - Open Policy Agent's Policy Language

## Overview

**Rego** is a declarative policy language purpose-built for expressing authorization policies. Created for Open Policy Agent (OPA), Rego makes it easy to write, test, and maintain complex authorization rules.

## Why Rego?

- **Declarative**: Describe what should be true, not how to compute it
- **Purpose-Built**: Designed specifically for policy decisions
- **Composable**: Build complex policies from simple rules
- **Testable**: First-class testing support
- **Human-Readable**: Easy to review and audit

## Basic Syntax

### Hello World

```rego
package example

# Simple rule
greeting := "Hello, World!"
```

### Rules

```rego
package authz

# Rule that always evaluates to true
allow {
    true
}

# Rule with condition
allow {
    input.user == "admin"
}

# Rule with multiple conditions (AND)
allow {
    input.user == "alice"
    input.action == "read"
    input.resource == "document"
}
```

### Variables

```rego
package example

# Simple assignment
user := "alice"

# From input
current_user := input.user

# Computed value
user_department := data.users[input.user].department
```

## Data Types

### Scalars

```rego
# String
name := "alice"

# Number
age := 30
price := 99.99

# Boolean
is_active := true

# Null
nothing := null
```

### Collections

```rego
# Array
colors := ["red", "green", "blue"]

# Set
unique_ids := {"abc", "def", "ghi"}

# Object
user := {
    "name": "Alice",
    "age": 30,
    "roles": ["admin", "editor"]
}

# Nested structures
organization := {
    "name": "Acme Corp",
    "departments": [
        {"name": "Engineering", "size": 50},
        {"name": "Sales", "size": 30}
    ]
}
```

## Input and Data

### Input

`input` contains the data sent with each query:

```json
{
  "user": "alice",
  "action": "read",
  "resource": "document:123"
}
```

```rego
allow {
    input.user == "alice"
    input.action == "read"
}
```

### Data

`data` contains policies and external data loaded into OPA:

```json
{
  "users": {
    "alice": {
      "role": "admin",
      "department": "engineering"
    },
    "bob": {
      "role": "viewer",
      "department": "sales"
    }
  }
}
```

```rego
allow {
    user := data.users[input.user]
    user.role == "admin"
}
```

## Operators

### Comparison

```rego
# Equality
x == y

# Inequality
x != y

# Less than / Greater than
x < y
x > y
x <= y
x >= y
```

### Logical

```rego
# AND (multiple expressions)
allow {
    input.user == "alice"  # AND
    input.action == "read" # AND
    input.time < deadline
}

# OR (multiple rules with same name)
allow {
    input.user == "admin"
}

allow {
    input.resource.owner == input.user
}

# NOT
deny {
    not allow
}
```

### Membership

```rego
# In array/set
"admin" in ["admin", "editor", "viewer"]

# Key in object
"role" in user
```

## Comprehensions

### Array Comprehension

```rego
# Get all admin users
admin_users := [user | user := data.users[_]; user.role == "admin"]

# Get all user emails
emails := [email | email := data.users[_].email]
```

### Object Comprehension

```rego
# Map user IDs to departments
user_departments := {id: dept |
    user := data.users[id]
    dept := user.department
}
```

### Set Comprehension

```rego
# Unique set of departments
departments := {dept |
    user := data.users[_]
    dept := user.department
}
```

## Functions

### Built-in Functions

```rego
# String functions
lower("HELLO")          # "hello"
upper("hello")          # "HELLO"
contains("hello", "ell") # true
startswith("hello", "hel") # true

# Array functions
count([1, 2, 3])        # 3
sum([1, 2, 3])          # 6
max([1, 5, 3])          # 5

# Set operations
intersection({"a", "b"}, {"b", "c"}) # {"b"}
union({"a"}, {"b"})                  # {"a", "b"}

# Type checking
is_string("hello")      # true
is_number(42)          # true
is_boolean(true)       # true
is_array([1, 2])       # true
is_object({"a": 1})    # true
```

### Custom Functions

```rego
# Simple function
is_admin(user) {
    data.users[user].role == "admin"
}

# Use it
allow {
    is_admin(input.user)
}

# Function with multiple parameters
has_permission(user, permission) {
    permissions := data.roles[data.users[user].role].permissions
    permission in permissions
}

# Use it
allow {
    has_permission(input.user, input.action)
}
```

## Real-World Examples

### Example 1: RBAC Policy

```rego
package rbac

import future.keywords.in

# Default deny
default allow = false

# Admins can do anything
allow {
    user_has_role("admin")
}

# Editors can read and write
allow {
    user_has_role("editor")
    input.action in ["read", "write"]
}

# Viewers can only read
allow {
    user_has_role("viewer")
    input.action == "read"
}

# Helper function
user_has_role(role) {
    data.user_roles[input.user][_] == role
}
```

**Test Input**:
```json
{
  "user": "alice",
  "action": "read"
}
```

**Test Data**:
```json
{
  "user_roles": {
    "alice": ["editor"],
    "bob": ["viewer"]
  }
}
```

### Example 2: Resource Ownership

```rego
package ownership

default allow = false

# Owner can do anything with their resource
allow {
    input.resource.owner == input.user
}

# Shared users can read
allow {
    input.action == "read"
    input.user in input.resource.shared_with
}
```

**Input**:
```json
{
  "user": "bob",
  "action": "read",
  "resource": {
    "id": "doc-123",
    "owner": "alice",
    "shared_with": ["bob", "carol"]
  }
}
```

### Example 3: Time-Based Access

```rego
package timebound

import future.keywords.if

default allow = false

# Allow during business hours
allow if {
    input.action == "read"
    is_business_hours
}

# Admins can access anytime
allow if {
    data.users[input.user].role == "admin"
}

# Helper: Check if current time is within business hours
is_business_hours {
    hour := time.clock(time.now_ns())[0]
    hour >= 9
    hour < 17
}
```

### Example 4: Multi-Tenant Access

```rego
package multitenant

default allow = false

# Users can only access resources in their tenant
allow {
    input.user_tenant == input.resource_tenant
    has_required_permission
}

# Check user has permission for action
has_required_permission {
    user := data.tenants[input.user_tenant].users[input.user]
    required_permission := data.permissions[input.resource_type][input.action]
    required_permission in user.permissions
}
```

**Input**:
```json
{
  "user": "alice",
  "user_tenant": "acme-corp",
  "resource_tenant": "acme-corp",
  "resource_type": "document",
  "action": "write"
}
```

### Example 5: Attribute-Based Access (ABAC)

```rego
package abac

import future.keywords.if

default allow = false

# Engineers can access engineering docs from corporate network
allow if {
    input.user.department == "engineering"
    input.resource.category == "engineering"
    input.action == "read"
    is_corporate_network
}

# Managers can access their department's docs
allow if {
    input.user.role == "manager"
    input.user.department == input.resource.department
}

# Check if request from corporate network
is_corporate_network {
    startswith(input.environment.ip, "10.0.")
}

# Check if during business hours
is_business_hours {
    hour := time.clock(time.now_ns())[0]
    9 <= hour
    hour < 17
}
```

## Advanced Patterns

### Partial Evaluation

```rego
# Generate set of allowed resources
allowed_resources[resource] {
    resource := data.resources[_]
    resource.owner == input.user
}

allowed_resources[resource] {
    resource := data.resources[_]
    input.user in resource.collaborators
}
```

### With Keyword (Testing)

```rego
package test

# Override data for testing
test_admin_access {
    allow with input as {"user": "admin", "action": "delete"}
    with data.users as {"admin": {"role": "admin"}}
}
```

### Every Keyword

```rego
# Check all conditions
all_conditions_met {
    every condition in required_conditions {
        condition == true
    }
}
```

### Some Keyword

```rego
# Check if any admin is online
has_online_admin {
    some user in data.users
    user.role == "admin"
    user.status == "online"
}
```

## Testing Rego Policies

### Unit Tests

```rego
package authz_test

import data.authz

# Test admin access
test_admin_can_delete {
    authz.allow with input as {
        "user": "alice",
        "action": "delete"
    }
    with data.users as {
        "alice": {"role": "admin"}
    }
}

# Test viewer cannot delete
test_viewer_cannot_delete {
    not authz.allow with input as {
        "user": "bob",
        "action": "delete"
    }
    with data.users as {
        "bob": {"role": "viewer"}
    }
}
```

Run tests:
```bash
opa test policy.rego policy_test.rego
```

## OPA CLI Usage

### Evaluate Policy

```bash
# Evaluate with input file
opa eval -i input.json -d policy.rego "data.authz.allow"

# Evaluate with inline input
opa eval -d policy.rego --input <(echo '{"user": "alice"}') "data.authz.allow"
```

### Run as Server

```bash
# Start OPA server
opa run --server policy.rego

# Query via REST API
curl -X POST http://localhost:8181/v1/data/authz/allow \
  -H 'Content-Type: application/json' \
  -d '{"input": {"user": "alice", "action": "read"}}'
```

### Format Code

```bash
opa fmt -w policy.rego
```

### Check Syntax

```bash
opa check policy.rego
```

## Best Practices

1. **Default Deny**: Always start with `default allow = false`
2. **Use Packages**: Organize policies in packages
3. **Meaningful Names**: Use descriptive rule names
4. **Comments**: Document complex logic
5. **Test Everything**: Write comprehensive tests
6. **Avoid Negation**: Use positive conditions when possible
7. **Helper Functions**: Extract reusable logic
8. **Type Safety**: Check types with `is_*` functions
9. **Performance**: Avoid unnecessary iterations
10. **Version Control**: Track policy changes in git

## Common Pitfalls

### 1. Undefined Variables

```rego
# BAD: typo in variable name
allow {
    inut.user == "alice"  # Should be input.user
}
```

### 2. Missing Default

```rego
# BAD: No default, undefined if no rule matches
allow {
    input.user == "admin"
}

# GOOD: Explicit default
default allow = false
allow {
    input.user == "admin"
}
```

### 3. Unintended OR Logic

```rego
# BAD: This creates OR logic (two separate rules)
allow {
    input.user == "alice"
}
allow {
    input.action == "read"
}
# Allows alice to do anything OR anyone to read

# GOOD: AND logic in single rule
allow {
    input.user == "alice"
    input.action == "read"
}
```

## Performance Tips

1. **Index Data**: Structure data for fast lookup
2. **Early Exit**: Put cheap checks first
3. **Avoid Wildcards**: Use specific paths when possible
4. **Cache**: OPA caches compiled policies
5. **Partial Evaluation**: Pre-compute when possible

## Integration Examples

### Kubernetes Admission Control

```rego
package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg := sprintf("Container %v must run as non-root", [container.name])
}
```

### API Gateway (Envoy/Istio)

```rego
package envoy.authz

default allow = false

allow {
    input.attributes.request.http.method == "GET"
    input.attributes.request.http.headers.authorization == expected_token
}
```

### Terraform/Cloud

```rego
package terraform

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.server_side_encryption_configuration
    msg := "S3 buckets must have encryption enabled"
}
```

## Tools and Resources

- **OPA Playground**: [play.openpolicyagent.org](https://play.openpolicyagent.org)
- **Rego Style Guide**: Official best practices
- **VS Code Extension**: OPA syntax highlighting
- **Regal**: Rego linter

## Further Reading

- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego Language Reference](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Policy Reference](https://www.openpolicyagent.org/docs/latest/policy-reference/)
- [OPA Book](https://www.openpolicyagent.org/docs/latest/books/)

## Next Steps

- Explore [OPA Framework](../../frameworks/opa/)
- Learn [Policy Making Techniques](../policy-standards/policy-making.md)
- Understand [ABAC](../concepts/abac.md)
- Review [Docker setup](./docker.md) for OPA containers
