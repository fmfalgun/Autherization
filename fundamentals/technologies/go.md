# Go Programming for Authorization

## Overview

**Go (Golang)** is widely used for building authorization services due to its performance, concurrency model, and strong standard library. Many authorization frameworks (OPA, Casbin, Ory) are written in Go.

## Why Go for Authorization?

- **Performance**: Fast execution, low latency for policy checks
- **Concurrency**: Built-in goroutines for handling multiple requests
- **Static Typing**: Catch errors at compile time
- **Simple Deployment**: Single binary, no runtime dependencies
- **Standard Library**: Excellent HTTP, JSON, and crypto support
- **Ecosystem**: Rich authorization libraries available

## Basic Authorization Patterns

### 1. Simple RBAC Implementation

```go
package main

import (
    "errors"
    "fmt"
)

// Permission represents an action that can be performed
type Permission string

const (
    PermRead   Permission = "read"
    PermWrite  Permission = "write"
    PermDelete Permission = "delete"
)

// Role represents a collection of permissions
type Role struct {
    Name        string
    Permissions []Permission
}

// User represents a system user with roles
type User struct {
    ID    string
    Email string
    Roles []Role
}

// HasPermission checks if user has a specific permission
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

// Authorization service
type AuthzService struct {
    roles map[string]Role
    users map[string]*User
}

func NewAuthzService() *AuthzService {
    return &AuthzService{
        roles: make(map[string]Role),
        users: make(map[string]*User),
    }
}

func (s *AuthzService) AddRole(role Role) {
    s.roles[role.Name] = role
}

func (s *AuthzService) AssignRole(userID, roleName string) error {
    user, exists := s.users[userID]
    if !exists {
        return errors.New("user not found")
    }

    role, exists := s.roles[roleName]
    if !exists {
        return errors.New("role not found")
    }

    user.Roles = append(user.Roles, role)
    return nil
}

func (s *AuthzService) CheckPermission(userID string, perm Permission) bool {
    user, exists := s.users[userID]
    if !exists {
        return false
    }
    return user.HasPermission(perm)
}

func main() {
    service := NewAuthzService()

    // Define roles
    admin := Role{
        Name:        "admin",
        Permissions: []Permission{PermRead, PermWrite, PermDelete},
    }
    editor := Role{
        Name:        "editor",
        Permissions: []Permission{PermRead, PermWrite},
    }
    viewer := Role{
        Name:        "viewer",
        Permissions: []Permission{PermRead},
    }

    service.AddRole(admin)
    service.AddRole(editor)
    service.AddRole(viewer)

    // Create user
    alice := &User{
        ID:    "1",
        Email: "alice@example.com",
    }
    service.users[alice.ID] = alice

    // Assign role
    service.AssignRole(alice.ID, "editor")

    // Check permissions
    fmt.Println(service.CheckPermission(alice.ID, PermRead))   // true
    fmt.Println(service.CheckPermission(alice.ID, PermWrite))  // true
    fmt.Println(service.CheckPermission(alice.ID, PermDelete)) // false
}
```

### 2. Resource Ownership Pattern

```go
package main

import "time"

type Resource struct {
    ID        string
    OwnerID   string
    SharedWith []string
    CreatedAt time.Time
}

type AuthzChecker struct {
    resources map[string]*Resource
}

func (a *AuthzChecker) CanAccess(userID, resourceID, action string) bool {
    resource, exists := a.resources[resourceID]
    if !exists {
        return false
    }

    // Owner can do anything
    if resource.OwnerID == userID {
        return true
    }

    // Shared users can read
    if action == "read" {
        for _, sharedUserID := range resource.SharedWith {
            if sharedUserID == userID {
                return true
            }
        }
    }

    return false
}
```

## Using Authorization Libraries

### Casbin

```go
package main

import (
    "fmt"
    "github.com/casbin/casbin/v2"
)

func main() {
    // Load model and policy
    enforcer, err := casbin.NewEnforcer("model.conf", "policy.csv")
    if err != nil {
        panic(err)
    }

    // Check permission
    sub := "alice"  // subject (user)
    obj := "data1"  // object (resource)
    act := "read"   // action

    ok, err := enforcer.Enforce(sub, obj, act)
    if err != nil {
        panic(err)
    }

    if ok {
        fmt.Println("Alice can read data1")
    } else {
        fmt.Println("Access denied")
    }

    // Add policy at runtime
    enforcer.AddPolicy("bob", "data2", "write")

    // Save policy
    enforcer.SavePolicy()
}
```

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
```
p, alice, data1, read
p, alice, data1, write
p, bob, data2, read
```

### OPA Client

```go
package main

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
)

type OPAClient struct {
    baseURL string
    client  *http.Client
}

type OPARequest struct {
    Input map[string]interface{} `json:"input"`
}

type OPAResponse struct {
    Result bool `json:"result"`
}

func NewOPAClient(baseURL string) *OPAClient {
    return &OPAClient{
        baseURL: baseURL,
        client:  &http.Client{},
    }
}

func (c *OPAClient) CheckPermission(ctx context.Context, input map[string]interface{}) (bool, error) {
    reqBody := OPARequest{Input: input}
    jsonData, err := json.Marshal(reqBody)
    if err != nil {
        return false, err
    }

    url := fmt.Sprintf("%s/v1/data/authz/allow", c.baseURL)
    req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
    if err != nil {
        return false, err
    }
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.client.Do(req)
    if err != nil {
        return false, err
    }
    defer resp.Body.Close()

    var opaResp OPAResponse
    if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
        return false, err
    }

    return opaResp.Result, nil
}

func main() {
    client := NewOPAClient("http://localhost:8181")

    input := map[string]interface{}{
        "user":     "alice",
        "action":   "read",
        "resource": "document:123",
    }

    allowed, err := client.CheckPermission(context.Background(), input)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Access allowed: %v\n", allowed)
}
```

## HTTP Middleware Pattern

### Authorization Middleware

```go
package main

import (
    "context"
    "net/http"
)

type contextKey string

const userIDKey contextKey = "userID"

// Authz middleware
func AuthzMiddleware(checker *AuthzChecker) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Get user from context (set by auth middleware)
            userID, ok := r.Context().Value(userIDKey).(string)
            if !ok {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            // Extract resource and action from request
            resourceID := r.URL.Query().Get("resource")
            action := r.Method

            // Check authorization
            if !checker.CanAccess(userID, resourceID, action) {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }

            // Authorized, proceed
            next.ServeHTTP(w, r)
        })
    }
}

// Permission-based middleware
func RequirePermission(perm Permission) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user, ok := r.Context().Value("user").(*User)
            if !ok {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            if !user.HasPermission(perm) {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}

// Usage
func main() {
    checker := &AuthzChecker{
        resources: make(map[string]*Resource),
    }

    mux := http.NewServeMux()

    // Protected endpoint
    mux.Handle("/api/resource", AuthzMiddleware(checker)(http.HandlerFunc(resourceHandler)))

    // Permission-based endpoint
    adminMux := http.NewServeMux()
    adminMux.HandleFunc("/admin/users", adminHandler)
    mux.Handle("/admin/", RequirePermission(PermDelete)(adminMux))

    http.ListenAndServe(":8080", mux)
}

func resourceHandler(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Access granted to resource"))
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Admin panel"))
}
```

## Context-Based Authorization

### Attribute-Based Access Control (ABAC)

```go
package main

import "time"

type Context struct {
    User        *User
    Resource    *Resource
    Action      string
    Environment *Environment
}

type Environment struct {
    Time      time.Time
    IPAddress string
    Location  string
}

type Policy interface {
    Evaluate(ctx *Context) bool
}

// Time-based policy
type BusinessHoursPolicy struct{}

func (p *BusinessHoursPolicy) Evaluate(ctx *Context) bool {
    hour := ctx.Environment.Time.Hour()
    return hour >= 9 && hour < 17
}

// Department-based policy
type DepartmentPolicy struct {
    AllowedDepartment string
}

func (p *DepartmentPolicy) Evaluate(ctx *Context) bool {
    // Check if user's department matches
    userDept := ctx.User.Attributes["department"]
    return userDept == p.AllowedDepartment
}

// Policy engine
type PolicyEngine struct {
    policies []Policy
}

func (e *PolicyEngine) Evaluate(ctx *Context) bool {
    for _, policy := range e.policies {
        if !policy.Evaluate(ctx) {
            return false
        }
    }
    return true
}

// User with attributes
type User struct {
    ID         string
    Attributes map[string]string
}

// Example usage
func main() {
    engine := &PolicyEngine{
        policies: []Policy{
            &BusinessHoursPolicy{},
            &DepartmentPolicy{AllowedDepartment: "engineering"},
        },
    }

    ctx := &Context{
        User: &User{
            ID:         "alice",
            Attributes: map[string]string{"department": "engineering"},
        },
        Environment: &Environment{
            Time: time.Now(),
        },
    }

    allowed := engine.Evaluate(ctx)
    println("Access allowed:", allowed)
}
```

## Advanced Patterns

### Policy Caching

```go
package main

import (
    "sync"
    "time"
)

type CachedPolicy struct {
    Result    bool
    ExpiresAt time.Time
}

type PolicyCache struct {
    mu    sync.RWMutex
    cache map[string]CachedPolicy
    ttl   time.Duration
}

func NewPolicyCache(ttl time.Duration) *PolicyCache {
    return &PolicyCache{
        cache: make(map[string]CachedPolicy),
        ttl:   ttl,
    }
}

func (c *PolicyCache) Get(key string) (bool, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()

    cached, exists := c.cache[key]
    if !exists {
        return false, false
    }

    if time.Now().After(cached.ExpiresAt) {
        return false, false
    }

    return cached.Result, true
}

func (c *PolicyCache) Set(key string, result bool) {
    c.mu.Lock()
    defer c.mu.Unlock()

    c.cache[key] = CachedPolicy{
        Result:    result,
        ExpiresAt: time.Now().Add(c.ttl),
    }
}

func (c *PolicyCache) makeKey(userID, action, resourceID string) string {
    return userID + ":" + action + ":" + resourceID
}
```

### Concurrent Permission Checks

```go
package main

import (
    "context"
    "sync"
)

type PermissionChecker struct {
    // ... fields
}

type CheckResult struct {
    Resource string
    Allowed  bool
    Error    error
}

func (p *PermissionChecker) CheckMultiple(ctx context.Context, userID string, resources []string) []CheckResult {
    results := make([]CheckResult, len(resources))
    var wg sync.WaitGroup

    for i, resource := range resources {
        wg.Add(1)
        go func(idx int, res string) {
            defer wg.Done()

            allowed, err := p.Check(ctx, userID, res)
            results[idx] = CheckResult{
                Resource: res,
                Allowed:  allowed,
                Error:    err,
            }
        }(i, resource)
    }

    wg.Wait()
    return results
}

func (p *PermissionChecker) Check(ctx context.Context, userID, resourceID string) (bool, error) {
    // Check logic here
    return true, nil
}
```

### Audit Logging

```go
package main

import (
    "encoding/json"
    "log"
    "time"
)

type AuditLog struct {
    Timestamp  time.Time `json:"timestamp"`
    UserID     string    `json:"user_id"`
    Action     string    `json:"action"`
    ResourceID string    `json:"resource_id"`
    Allowed    bool      `json:"allowed"`
    Reason     string    `json:"reason,omitempty"`
}

type AuditLogger struct {
    // logger implementation
}

func (a *AuditLogger) Log(entry AuditLog) {
    entry.Timestamp = time.Now()
    data, _ := json.Marshal(entry)
    log.Println(string(data))
}

// Usage in authorization check
func (s *AuthzService) CheckWithAudit(userID, action, resourceID string) bool {
    allowed := s.CheckPermission(userID, Permission(action))

    s.audit.Log(AuditLog{
        UserID:     userID,
        Action:     action,
        ResourceID: resourceID,
        Allowed:    allowed,
        Reason:     "RBAC policy evaluation",
    })

    return allowed
}
```

## Testing Authorization Logic

### Unit Tests

```go
package main

import (
    "testing"
)

func TestUserHasPermission(t *testing.T) {
    tests := []struct {
        name       string
        user       *User
        permission Permission
        want       bool
    }{
        {
            name: "admin has delete permission",
            user: &User{
                Roles: []Role{
                    {Name: "admin", Permissions: []Permission{PermDelete}},
                },
            },
            permission: PermDelete,
            want:       true,
        },
        {
            name: "viewer does not have write permission",
            user: &User{
                Roles: []Role{
                    {Name: "viewer", Permissions: []Permission{PermRead}},
                },
            },
            permission: PermWrite,
            want:       false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := tt.user.HasPermission(tt.permission)
            if got != tt.want {
                t.Errorf("HasPermission() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Integration Tests

```go
func TestAuthzServiceIntegration(t *testing.T) {
    service := NewAuthzService()

    // Setup
    adminRole := Role{Name: "admin", Permissions: []Permission{PermRead, PermWrite, PermDelete}}
    service.AddRole(adminRole)

    user := &User{ID: "1", Email: "test@example.com"}
    service.users[user.ID] = user
    service.AssignRole(user.ID, "admin")

    // Test
    if !service.CheckPermission(user.ID, PermDelete) {
        t.Error("Admin should have delete permission")
    }
}
```

## Best Practices

1. **Fail Secure**: Default to deny
2. **Separate Concerns**: Keep authz logic separate from business logic
3. **Centralize**: Single source of truth for permissions
4. **Cache Wisely**: Cache policy decisions with TTL
5. **Audit**: Log all authorization decisions
6. **Test Thoroughly**: Unit and integration tests
7. **Use Interfaces**: Abstract authorization logic
8. **Context**: Pass context.Context for cancellation
9. **Errors**: Return meaningful errors
10. **Performance**: Use concurrent checks when possible

## Libraries and Frameworks

- **[Casbin](https://github.com/casbin/casbin)**: Powerful authorization library
- **[Ory Ladon](https://github.com/ory/ladon)**: SDK for access control policies
- **[Permify](https://github.com/Permify/permify)**: Relationship-based access control
- **[go-rbac](https://github.com/mikespook/gorbac)**: Simple RBAC implementation
- **[OPA Go SDK](https://github.com/open-policy-agent/opa)**: Embed OPA in Go

## Further Reading

- [Effective Go](https://go.dev/doc/effective_go)
- [Go Concurrency Patterns](https://go.dev/blog/pipelines)
- [Casbin Documentation](https://casbin.org/docs/overview)
- [Authorization in Go](https://www.calhoun.io/intro-to-authorization-in-go/)

## Next Steps

- Explore [OPA integration](../../frameworks/opa/)
- Learn [Casbin](../../frameworks/casbin/)
- Review [RBAC patterns](../concepts/rbac.md)
- Understand [Docker deployment](./docker.md)
