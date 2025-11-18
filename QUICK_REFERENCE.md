# Quick Reference Guide

## Authorization Models At a Glance

### RBAC (Role-Based Access Control)
```
Users → Roles → Permissions → Resources
```
**When**: Clear hierarchies, stable permissions
**Example**: Admin, Editor, Viewer roles

### ABAC (Attribute-Based Access Control)
```
Decision = f(User Attributes, Resource Attributes, Environment, Action)
```
**When**: Dynamic rules, context matters
**Example**: "Engineers can access engineering docs during business hours"

### ReBAC (Relationship-Based Access Control)
```
(Subject, Relation, Object) → Permission Graph
```
**When**: Social features, complex sharing
**Example**: Google Drive-like permissions

---

## Framework Quick Comparison

| Framework | Use When | Difficulty | Performance |
|-----------|----------|------------|-------------|
| **OPA** | Cloud-native, K8s | Medium | ⚡⚡⚡ |
| **Casbin** | Simple RBAC/ABAC | Low | ⚡⚡⚡ |
| **Keycloak** | Need full IAM + SSO | High | ⚡⚡ |
| **OSO** | App-level, data filtering | Medium | ⚡⚡⚡ |
| **SpiceDB** | Complex relationships | Medium | ⚡⚡ |
| **CASL** | JavaScript apps | Low | ⚡⚡⚡ |

---

## Common Patterns

### 1. Owner-Based
```javascript
allow if resource.owner == user.id
```

### 2. Role-Based
```javascript
allow if user.role in ["admin", "editor"]
```

### 3. Attribute-Based
```javascript
allow if user.department == resource.department
  && time.hour >= 9 && time.hour < 17
```

### 4. Relationship-Based
```javascript
allow if (user, viewer, resource) OR
           (user, editor, resource) OR
           (user, owner, resource)
```

---

## OPA (Rego) Cheatsheet

### Basic Structure
```rego
package authz

# Default deny
default allow = false

# Allow rule
allow {
    input.user.role == "admin"
}

# Multiple conditions (AND)
allow {
    input.user.role == "editor"
    input.action in ["read", "write"]
}

# OR logic (multiple rules)
allow { input.user.role == "admin" }
allow { input.resource.owner == input.user.id }
```

### Common Patterns
```rego
# Check membership
allow { input.user.id in data.allowed_users }

# Time-based
allow {
    hour := time.clock(time.now_ns())[0]
    hour >= 9
    hour < 17
}

# Nested attributes
allow { data.users[input.user.id].department == "engineering" }
```

---

## Casbin Cheatsheet

### Model File
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

### Policy File (CSV)
```csv
p, alice, data1, read
p, alice, data1, write
p, bob, data2, read
g, alice, admin
```

### Code
```go
e, _ := casbin.NewEnforcer("model.conf", "policy.csv")
ok, _ := e.Enforce("alice", "data1", "read")
```

---

## CASL Cheatsheet

### Define Abilities
```javascript
import { AbilityBuilder, Ability } from '@casl/ability';

function defineAbilitiesFor(user) {
    const { can, cannot, build } = new AbilityBuilder(Ability);

    if (user.role === 'admin') {
        can('manage', 'all');
    } else {
        can('read', 'Article');
        can('update', 'Article', { authorId: user.id });
    }

    return build();
}
```

### Check Permissions
```javascript
const ability = defineAbilitiesFor(user);

ability.can('read', 'Article');              // true
ability.can('update', article);               // checks conditions
ability.can('delete', 'Article');             // false
```

### React
```jsx
<Can I="edit" this={article}>
    <button>Edit</button>
</Can>
```

---

## JWT Quick Reference

### Structure
```
header.payload.signature
```

### Header
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

### Payload
```json
{
  "sub": "1234567890",
  "name": "Alice",
  "role": "admin",
  "iat": 1516239022,
  "exp": 1516242622
}
```

### Validation Checklist
- [ ] Verify signature
- [ ] Check expiration (`exp`)
- [ ] Validate issuer (`iss`)
- [ ] Validate audience (`aud`)
- [ ] Check not-before (`nbf`)
- [ ] Validate algorithm

---

## OAuth 2.0 Flows

### Authorization Code (Most Secure)
```
1. User → App: Click "Login"
2. App → AuthZ Server: Redirect to login
3. User → AuthZ Server: Authenticate
4. AuthZ Server → App: Code
5. App → AuthZ Server: Exchange code for token
6. AuthZ Server → App: Access token
```

### Client Credentials (M2M)
```
1. Service → AuthZ Server: Client credentials
2. AuthZ Server → Service: Access token
3. Service → API: Request with token
```

---

## Security Checklist

### General
- [ ] Default deny
- [ ] Least privilege
- [ ] Server-side validation
- [ ] Comprehensive audit logging
- [ ] Regular access reviews

### Tokens
- [ ] Short expiration (15-60 min)
- [ ] Secure storage (not localStorage)
- [ ] HTTPS only
- [ ] Validate all claims
- [ ] Strong signing algorithm

### Policies
- [ ] Version controlled
- [ ] Tested thoroughly
- [ ] Reviewed by security team
- [ ] No hardcoded secrets
- [ ] Documented clearly

---

## Common Mistakes to Avoid

### ❌ Don't
```javascript
// Client-side only authorization
if (user.isAdmin) {
    deleteButton.show();  // Can be bypassed!
}

// Accepting role from client
user.role = request.body.role;  // DANGEROUS!

// No validation
const token = request.headers.authorization;
const user = decodeToken(token);  // No verification!
```

### ✅ Do
```javascript
// Server validates
app.delete('/posts/:id', async (req, res) => {
    const post = await Post.findById(req.params.id);
    if (!ability.can('delete', post)) {
        return res.status(403).send('Forbidden');
    }
    await post.delete();
});

// Server controls roles
// Separate admin endpoint for role changes

// Validate tokens
const token = request.headers.authorization;
const user = verifyToken(token);  // Checks signature, exp, etc.
```

---

## Performance Tips

### OPA
- Cache policy decisions
- Use partial evaluation
- Batch checks when possible
- Index data efficiently

### Casbin
- Enable caching
- Use batch operations
- Database indexes
- Watcher for sync

### General
- Cache authorization decisions (short TTL)
- Batch permission checks
- Async processing when possible
- Monitor latency

---

## Debugging Commands

### OPA
```bash
# Test policy
opa test policy.rego policy_test.rego

# Evaluate
opa eval -d policy.rego -i input.json "data.authz.allow"

# Check syntax
opa check policy.rego

# Format
opa fmt -w policy.rego
```

### Casbin
```bash
# In code
e.GetPolicy()                    # See all policies
e.GetRolesForUser("alice")       # See user roles
e.GetPermissionsForUser("alice") # See permissions
```

### JWT
```bash
# Decode (jwt.io or command line)
echo $TOKEN | cut -d. -f2 | base64 -d | jq

# Verify
# Use language-specific libraries, not online tools for real tokens!
```

---

## Quick Decision Trees

### Which Authorization Model?

```
Do you have clear, stable roles?
├─ Yes → RBAC
└─ No
    ├─ Need context (time, location)?
    │  └─ Yes → ABAC
    └─ Need relationships/sharing?
       └─ Yes → ReBAC
```

### Which Framework?

```
What's your primary use case?
├─ Kubernetes/Cloud-Native → OPA
├─ Simple RBAC → Casbin
├─ Enterprise SSO + Auth → Keycloak
├─ JavaScript full-stack → CASL
├─ Google Drive-like → SpiceDB
└─ Application-level → OSO
```

---

## HTTP Status Codes

```
401 Unauthorized   → Not authenticated (no/invalid token)
403 Forbidden      → Authenticated but not authorized
404 Not Found      → Resource doesn't exist (or hiding it)
200 OK             → Authorized and successful
```

---

## Useful Commands

### Docker
```bash
# Run OPA
docker run -p 8181:8181 openpolicyagent/opa run --server

# Run Keycloak
docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev
```

### Kubernetes
```bash
# Check RBAC
kubectl auth can-i delete pods --as=alice

# Describe role
kubectl describe role pod-reader
```

---

## Regular Expressions for Patterns

### Email
```regex
^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$
```

### Resource Patterns
```regex
# Rego
startswith(input.path, "/api/v1/users/")

# Casbin
keyMatch("/api/v1/users/*", "/api/v1/users/123")
```

---

## Glossary (Top Terms)

- **AuthN**: Authentication (who you are)
- **AuthZ**: Authorization (what you can do)
- **JWT**: JSON Web Token
- **RBAC**: Role-Based Access Control
- **ABAC**: Attribute-Based Access Control
- **ReBAC**: Relationship-Based Access Control
- **PEP**: Policy Enforcement Point
- **PDP**: Policy Decision Point
- **SSO**: Single Sign-On
- **MFA**: Multi-Factor Authentication

---

## One-Liners

```bash
# Generate random secret
openssl rand -base64 32

# Create JWT (example, use libraries in production)
# Don't actually do this - use proper libraries!

# Hash password (bcrypt example)
# Use bcrypt.hash() in your language

# Check if port is in use
lsof -i :8181
```

---

## Resources Quick Links

- [Main README](./README.md)
- [Learning Path](./LEARNING_PATH.md)
- [Glossary](./GLOSSARY.md)
- [Security Guide](./SECURITY.md)
- [Comparison](./COMPARISON.md)
- [All Resources](./RESOURCES.md)

---

**Print this for quick reference! 📋**

---

**Last Updated**: 2025-11-16
