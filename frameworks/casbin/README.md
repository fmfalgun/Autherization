# Casbin

## Overview

**Casbin** is an authorization library that supports multiple access control models including ACL, RBAC, ABAC, and RESTful. It's designed to be simple, powerful, and efficient, with support for over 50 programming languages.

**Website**: [casbin.org](https://casbin.org/)
**GitHub**: [github.com/casbin/casbin](https://github.com/casbin/casbin)
**License**: Apache 2.0

## Why Casbin?

- **Multi-Model**: Supports ACL, RBAC, ABAC, RESTful, and custom models
- **Multi-Language**: 50+ languages (Go, Java, Python, Node.js, PHP, .NET, Rust)
- **Flexible**: Customize access control model for your needs
- **Performance**: Sub-millisecond policy evaluation
- **Adapters**: 50+ storage adapters (SQL, NoSQL, cloud)
- **Simple API**: Easy to integrate and use
- **Battle-Tested**: Used by companies like VMware, Cisco, Tencent

## Use Cases

- **Web Applications**: Traditional RBAC for apps
- **API Authorization**: RESTful access control
- **Multi-Tenancy**: Tenant isolation
- **Microservices**: Distributed authorization
- **Cloud IAM**: Cloud resource permissions
- **Database Access**: Row-level security

## Core Concepts

### PERM Model

Casbin uses **PERM** (Policy, Effect, Request, Matchers) metamodel:

```
┌──────────────────────────────────────┐
│          Request (r)                 │
│  What the user wants to do           │
└──────────────────┬───────────────────┘
                   │
                   ▼
┌──────────────────────────────────────┐
│          Policy (p)                  │
│  Stored access control rules         │
└──────────────────┬───────────────────┘
                   │
                   ▼
┌──────────────────────────────────────┐
│         Matchers (m)                 │
│  Logic to match request with policy  │
└──────────────────┬───────────────────┘
                   │
                   ▼
┌──────────────────────────────────────┐
│          Effect (e)                  │
│  Final decision (allow/deny)         │
└──────────────────────────────────────┘
```

### Model File

Defines the access control model structure:

```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
```

### Policy File

Contains the actual access control data:

```csv
p, alice, data1, read
p, alice, data1, write
p, bob, data2, read
```

## Quick Start

### Installation

#### Go
```bash
go get github.com/casbin/casbin/v2
```

#### Python
```bash
pip install casbin
```

#### Node.js
```bash
npm install casbin
```

#### Java
```xml
<dependency>
    <groupId>org.casbin</groupId>
    <artifactId>jcasbin</artifactId>
    <version>1.x.x</version>
</dependency>
```

### Basic Example (ACL)

**model.conf**:
```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
```

**policy.csv**:
```csv
p, alice, data1, read
p, alice, data1, write
p, bob, data2, read
```

**Go Code**:
```go
package main

import (
    "fmt"
    "github.com/casbin/casbin/v2"
)

func main() {
    // Load model and policy
    e, err := casbin.NewEnforcer("model.conf", "policy.csv")
    if err != nil {
        panic(err)
    }

    // Check permissions
    ok, _ := e.Enforce("alice", "data1", "read")
    fmt.Println("Alice can read data1:", ok) // true

    ok, _ = e.Enforce("alice", "data1", "write")
    fmt.Println("Alice can write data1:", ok) // true

    ok, _ = e.Enforce("bob", "data1", "read")
    fmt.Println("Bob can read data1:", ok) // false

    ok, _ = e.Enforce("bob", "data2", "read")
    fmt.Println("Bob can read data2:", ok) // true
}
```

## Access Control Models

### 1. ACL (Access Control List)

Simplest model - direct user-resource-action mapping.

**model.conf**:
```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
```

**Example**:
```go
e.AddPolicy("alice", "data1", "read")
e.AddPolicy("bob", "data2", "write")
```

### 2. RBAC (Role-Based Access Control)

Users assigned to roles, roles have permissions.

**model.conf**:
```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
```

**policy.csv**:
```csv
p, admin, data, read
p, admin, data, write
p, editor, data, read
p, editor, data, write
p, viewer, data, read

g, alice, admin
g, bob, editor
g, carol, viewer
```

**Example**:
```go
// Check permission
e.Enforce("alice", "data", "write") // true (alice is admin)
e.Enforce("bob", "data", "write")   // true (bob is editor)
e.Enforce("carol", "data", "write") // false (carol is viewer)

// Get user roles
roles := e.GetRolesForUser("alice") // ["admin"]

// Get users for role
users := e.GetUsersForRole("admin") // ["alice"]
```

### 3. RBAC with Domains (Multi-Tenancy)

Separate permissions per domain/tenant.

**model.conf**:
```ini
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
```

**policy.csv**:
```csv
p, admin, domain1, data, read
p, admin, domain1, data, write
p, admin, domain2, data, read

g, alice, admin, domain1
g, bob, admin, domain2
```

**Example**:
```go
// Alice is admin in domain1
e.Enforce("alice", "domain1", "data", "write") // true

// Alice is NOT admin in domain2
e.Enforce("alice", "domain2", "data", "write") // false

// Bob is admin in domain2
e.Enforce("bob", "domain2", "data", "write") // true
```

### 4. ABAC (Attribute-Based Access Control)

Decisions based on attributes.

**model.conf**:
```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub_rule, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = eval(p.sub_rule) && r.obj == p.obj && r.act == p.act
```

**policy.csv**:
```csv
p, r.sub.Age > 18, data, read
p, r.sub.Department == "Engineering", code, write
```

**Example**:
```go
type User struct {
    Name       string
    Age        int
    Department string
}

alice := User{Name: "alice", Age: 25, Department: "Engineering"}
bob := User{Name: "bob", Age: 16, Department: "Sales"}

e.Enforce(alice, "data", "read")    // true (age > 18)
e.Enforce(bob, "data", "read")      // false (age < 18)
e.Enforce(alice, "code", "write")   // true (Engineering)
```

### 5. RESTful

Match RESTful API paths.

**model.conf**:
```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)
```

**policy.csv**:
```csv
p, alice, /api/v1/users/*, GET
p, alice, /api/v1/users/*, POST
p, bob, /api/v1/products/*, GET
```

**Example**:
```go
e.Enforce("alice", "/api/v1/users/123", "GET")  // true
e.Enforce("alice", "/api/v1/users/456", "POST") // true
e.Enforce("bob", "/api/v1/users/123", "GET")    // false
e.Enforce("bob", "/api/v1/products/1", "GET")   // true
```

## RBAC with Hierarchies

**model.conf** (same as RBAC):
```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
```

**policy.csv** (with role inheritance):
```csv
# Permissions
p, super_admin, data, read
p, super_admin, data, write
p, super_admin, data, delete
p, admin, data, read
p, admin, data, write
p, user, data, read

# Role hierarchy
g, admin, user        # admin inherits user permissions
g, super_admin, admin # super_admin inherits admin permissions

# User assignments
g, alice, super_admin
g, bob, admin
g, carol, user
```

**Example**:
```go
// Alice (super_admin) can do everything
e.Enforce("alice", "data", "delete") // true

// Bob (admin) can read and write (inherits from user)
e.Enforce("bob", "data", "write") // true
e.Enforce("bob", "data", "delete") // false

// Carol (user) can only read
e.Enforce("carol", "data", "read") // true
e.Enforce("carol", "data", "write") // false
```

## Storage Adapters

Casbin supports 50+ storage adapters:

### Database Adapters

```go
// MySQL
import "github.com/casbin/mysql-adapter"
a := mysqladapter.NewAdapter("mysql", "user:pass@tcp(127.0.0.1:3306)/")

// PostgreSQL
import "github.com/casbin/postgres-adapter"
a := postgresadapter.NewAdapter("postgres://user:pass@localhost/casbin")

// MongoDB
import "github.com/casbin/mongodb-adapter"
a := mongodbadapter.NewAdapter("mongodb://localhost:27017")

// Redis
import "github.com/casbin/redis-adapter"
a := redisadapter.NewAdapter("tcp", "localhost:6379")

// Use adapter
e, _ := casbin.NewEnforcer("model.conf", a)
```

### File Adapters

```go
// CSV (default)
e, _ := casbin.NewEnforcer("model.conf", "policy.csv")

// JSON
import "github.com/casbin/json-adapter"
a := jsonadapter.NewAdapter("policy.json")
```

### Cloud Adapters

```go
// AWS S3
import "github.com/casbin/aws-s3-adapter"
a := awss3adapter.NewAdapter(s3Client, "bucket", "policy.csv")

// Azure Blob
import "github.com/casbin/azure-blob-adapter"
a := azureblobadapter.NewAdapter(connectionString, "container", "policy.csv")
```

## Watchers (Multi-Instance Sync)

Keep multiple Casbin instances in sync:

```go
import "github.com/casbin/redis-watcher"

// Create watcher
w := rediswatcher.NewWatcher("localhost:6379")

// Set watcher
e.SetWatcher(w)

// Set callback for policy changes
w.SetUpdateCallback(func(msg string) {
    // Reload policy when notified
    e.LoadPolicy()
})

// Now when you update policy on one instance:
e.AddPolicy("alice", "data", "write")
// All other instances will be notified and reload
```

## Middleware Integration

### HTTP Middleware (Go)

```go
package main

import (
    "net/http"
    "github.com/casbin/casbin/v2"
)

func AuthzMiddleware(e *casbin.Enforcer) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Get user from context (set by auth middleware)
            user := r.Context().Value("user").(string)

            // Check authorization
            ok, err := e.Enforce(user, r.URL.Path, r.Method)
            if err != nil {
                http.Error(w, "Internal error", http.StatusInternalServerError)
                return
            }

            if !ok {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}

func main() {
    e, _ := casbin.NewEnforcer("model.conf", "policy.csv")

    mux := http.NewServeMux()
    mux.HandleFunc("/api/data", dataHandler)

    http.ListenAndServe(":8080", AuthzMiddleware(e)(mux))
}
```

### Gin Framework

```go
import (
    "github.com/gin-gonic/gin"
    "github.com/casbin/casbin/v2"
)

func Authorize(e *casbin.Enforcer) gin.HandlerFunc {
    return func(c *gin.Context) {
        user := c.GetString("user")
        obj := c.Request.URL.Path
        act := c.Request.Method

        ok, _ := e.Enforce(user, obj, act)
        if !ok {
            c.AbortWithStatus(http.StatusForbidden)
            return
        }

        c.Next()
    }
}

func main() {
    r := gin.Default()
    e, _ := casbin.NewEnforcer("model.conf", "policy.csv")

    // Apply to specific routes
    r.GET("/api/data", Authorize(e), dataHandler)

    // Or to route groups
    api := r.Group("/api", Authorize(e))
    {
        api.GET("/users", getUsers)
        api.POST("/users", createUser)
    }

    r.Run()
}
```

### Echo Framework

```go
import (
    "github.com/labstack/echo/v4"
    "github.com/casbin/casbin/v2"
)

func AuthzMiddleware(e *casbin.Enforcer) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            user := c.Get("user").(string)

            ok, _ := e.Enforce(user, c.Path(), c.Request().Method)
            if !ok {
                return echo.ErrForbidden
            }

            return next(c)
        }
    }
}
```

### Django (Python)

```python
from casbin import Enforcer
from django.http import HttpResponseForbidden

enforcer = Enforcer("model.conf", "policy.csv")

def casbin_middleware(get_response):
    def middleware(request):
        user = request.user.username
        path = request.path
        method = request.method

        if not enforcer.enforce(user, path, method):
            return HttpResponseForbidden("Access denied")

        response = get_response(request)
        return response

    return middleware
```

### Express (Node.js)

```javascript
const casbin = require('casbin');

async function authorize(req, res, next) {
    const enforcer = await casbin.newEnforcer('model.conf', 'policy.csv');

    const user = req.user.name;
    const path = req.path;
    const method = req.method;

    const allowed = await enforcer.enforce(user, path, method);

    if (!allowed) {
        return res.status(403).send('Forbidden');
    }

    next();
}

app.use(authorize);
```

## Management API

### Policy Management

```go
// Add policy
e.AddPolicy("alice", "data1", "read")

// Add policies (batch)
e.AddPolicies([][]string{
    {"alice", "data1", "read"},
    {"bob", "data2", "write"},
})

// Remove policy
e.RemovePolicy("alice", "data1", "read")

// Remove filtered policies
e.RemoveFilteredPolicy(1, "data1") // Remove all policies for data1

// Get all policies
policies := e.GetPolicy()

// Update policy
e.UpdatePolicy(
    []string{"alice", "data1", "read"},
    []string{"alice", "data1", "write"},
)
```

### Role Management

```go
// Add role for user
e.AddRoleForUser("alice", "admin")

// Add role with domain
e.AddRoleForUserInDomain("alice", "admin", "domain1")

// Get roles for user
roles := e.GetRolesForUser("alice")

// Get users for role
users := e.GetUsersForRole("admin")

// Delete role for user
e.DeleteRoleForUser("alice", "admin")

// Delete all roles for user
e.DeleteRolesForUser("alice")

// Check if user has role
has := e.HasRoleForUser("alice", "admin")
```

### Permission Management

```go
// Get permissions for user
perms := e.GetPermissionsForUser("alice")
// Returns: [["alice", "data1", "read"], ["alice", "data2", "write"]]

// Get implicit permissions (including from roles)
implicitPerms := e.GetImplicitPermissionsForUser("alice")

// Check if user has permission
has := e.HasPermissionForUser("alice", "data1", "read")

// Add permission for user
e.AddPermissionForUser("alice", "data1", "read")

// Delete permission for user
e.DeletePermissionForUser("alice", "data1", "read")

// Delete all permissions for user
e.DeletePermissionsForUser("alice")
```

## Performance Optimization

### 1. Enable Auto-Save

```go
// Auto-save to adapter after each change
e.EnableAutoSave(true)
```

### 2. Batch Operations

```go
// Add multiple policies at once
e.AddPolicies([][]string{
    {"alice", "data1", "read"},
    {"alice", "data2", "write"},
    {"bob", "data3", "read"},
})
```

### 3. Caching

```go
// Use built-in cache (enabled by default)
e.EnableCache(true)
```

### 4. Load Policy Once

```go
// Load policy at startup
e.LoadPolicy()

// Then use in-memory enforcement
ok, _ := e.Enforce("alice", "data1", "read")
```

## Testing

```go
package main

import (
    "testing"
    "github.com/casbin/casbin/v2"
)

func TestEnforcement(t *testing.T) {
    e, _ := casbin.NewEnforcer("model.conf", "policy.csv")

    tests := []struct {
        sub    string
        obj    string
        act    string
        expect bool
    }{
        {"alice", "data1", "read", true},
        {"alice", "data1", "write", true},
        {"bob", "data1", "read", false},
        {"bob", "data2", "read", true},
    }

    for _, tt := range tests {
        ok, _ := e.Enforce(tt.sub, tt.obj, tt.act)
        if ok != tt.expect {
            t.Errorf("Enforce(%s, %s, %s) = %v, want %v",
                tt.sub, tt.obj, tt.act, ok, tt.expect)
        }
    }
}
```

## Docker Deployment

### Dockerfile

```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o casbin-service .

FROM alpine:latest

COPY --from=builder /app/casbin-service /casbin-service
COPY model.conf /model.conf
COPY policy.csv /policy.csv

EXPOSE 8080
CMD ["/casbin-service"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  casbin-service:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./model.conf:/model.conf:ro
      - ./policy.csv:/policy.csv:ro
    environment:
      - DB_HOST=postgres
      - DB_PORT=5432
    depends_on:
      - postgres

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: casbin
      POSTGRES_USER: casbin
      POSTGRES_PASSWORD: secret
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

## Best Practices

1. **Separate Model from Policy**: Keep model definition in code/config, policies in database
2. **Use Adapters**: Don't use file-based policies in production
3. **Enable Watchers**: For multi-instance deployments
4. **Cache Policies**: Enable auto-caching for performance
5. **Batch Operations**: Use batch APIs for bulk updates
6. **Test Thoroughly**: Write unit tests for all access control scenarios
7. **Monitor Performance**: Track enforcement latency
8. **Version Models**: Track changes to model files
9. **Audit Policies**: Log all policy changes
10. **Use Domains**: For multi-tenancy isolation

## Comparison with Other Frameworks

| Feature | Casbin | OPA | Keycloak |
|---------|--------|-----|----------|
| **Simplicity** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| **Flexibility** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Performance** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Multi-Language** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Cloud-Native** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |

## Further Resources

- **Documentation**: [casbin.org/docs](https://casbin.org/docs/overview)
- **Editor**: [casbin.org/editor](https://casbin.org/editor)
- **Examples**: [github.com/casbin/casbin/examples](https://github.com/casbin/casbin/tree/master/examples)
- **Forum**: [forum.casbin.com](https://forum.casbin.com/)

## Community

- **Gitter**: [gitter.im/casbin/lobby](https://gitter.im/casbin/lobby)
- **Stack Overflow**: Tag `casbin`
- **GitHub Discussions**: [github.com/casbin/casbin/discussions](https://github.com/casbin/casbin/discussions)

## Next Steps

- Review [RBAC Concepts](../../fundamentals/concepts/rbac.md)
- Understand [Policy Making](../../fundamentals/policy-standards/policy-making.md)
- Compare with [OPA](../opa/README.md)
- Check [Comparative Analysis](../../COMPARISON.md)
