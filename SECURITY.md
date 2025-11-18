# Security Best Practices for Authorization Systems

## Overview

This document provides comprehensive security guidance for implementing and operating authorization systems. Authorization is a critical security control - mistakes can lead to data breaches, privilege escalation, and compliance violations.

---

## 🔐 Core Security Principles

### 1. Default Deny
**Always start with deny, explicitly grant access**

```rego
# GOOD
default allow = false

allow {
    input.user.role == "admin"
}

# BAD
default allow = true

deny {
    input.user.role == "banned"
}
```

### 2. Least Privilege
**Grant minimum permissions necessary**

```yaml
# GOOD
role: editor
permissions:
  - read:articles
  - write:own-articles
  - update:own-articles

# BAD
role: editor
permissions:
  - read:*
  - write:*
  - update:*
  - delete:*
```

### 3. Defense in Depth
**Multiple layers of security controls**

```
┌─────────────────────────────┐
│   Application Layer         │
│   (CASL, Casbin)           │
├─────────────────────────────┤
│   API Gateway               │
│   (OPA, Rate Limiting)     │
├─────────────────────────────┤
│   Service Mesh              │
│   (Istio, mTLS)            │
├─────────────────────────────┤
│   Database                  │
│   (Row-level security)     │
└─────────────────────────────┘
```

### 4. Separation of Duties
**Prevent conflicts of interest**

```yaml
policies:
  - name: no_self_approval
    deny:
      condition: approver.id == requester.id

  - name: mutual_exclusion
    roles:
      cannot_both_have: [auditor, finance_manager]
```

### 5. Fail Secure
**Default to secure state on errors**

```go
func authorize(user, resource, action string) bool {
    result, err := checkPermission(user, resource, action)
    if err != nil {
        log.Error("Authorization check failed", err)
        return false  // SECURE: Deny on error
    }
    return result
}
```

---

## 🛡️ Authentication Integration

### Verify Before Authorize

```go
func handleRequest(w http.ResponseWriter, r *http.Request) {
    // 1. AUTHENTICATE first
    user, err := authenticate(r)
    if err != nil {
        http.Error(w, "Unauthorized", 401)
        return
    }

    // 2. Then AUTHORIZE
    if !authorize(user, resource, action) {
        http.Error(w, "Forbidden", 403)
        return
    }

    // 3. Process request
    processRequest(w, r, user)
}
```

### Never Trust Client-Side Authorization

```javascript
// ❌ BAD: Client-side only
function deletePost(postId) {
    if (user.role === 'admin') {  // Can be manipulated!
        api.delete(`/posts/${postId}`);
    }
}

// ✅ GOOD: Server validates
function deletePost(postId) {
    // Client can show/hide UI
    if (ability.can('delete', 'Post')) {
        // But server MUST validate
        api.delete(`/posts/${postId}`);  // Server checks again
    }
}
```

---

## 🔑 Token Security

### Access Token Best Practices

1. **Short Expiration**
   ```json
   {
     "exp": 1700003600,  // 15-60 minutes
     "iat": 1700000000
   }
   ```

2. **Secure Storage**
   ```javascript
   // ❌ BAD
   localStorage.setItem('token', accessToken);

   // ✅ GOOD
   // Store in memory only, or HttpOnly cookie
   let accessToken = null;  // Memory
   ```

3. **Strong Signing**
   ```go
   // Use strong algorithms
   token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
   // NOT: jwt.SigningMethodNone or weak HMAC
   ```

4. **Validate Everything**
   ```go
   // Check all claims
   if time.Now().Unix() > claims.ExpiresAt {
       return errors.New("token expired")
   }
   if claims.Issuer != expectedIssuer {
       return errors.New("invalid issuer")
   }
   if !contains(claims.Audience, expectedAudience) {
       return errors.New("invalid audience")
   }
   ```

### Refresh Token Security

```go
type RefreshToken struct {
    Token     string    // Hashed, never plain text
    UserID    string
    ExpiresAt time.Time
    Revoked   bool
    DeviceID  string    // Bind to device
    IPAddress string    // Track origin
}

// Store hashed
func storeRefreshToken(token string, userID string) {
    hashed := sha256.Sum256([]byte(token))
    db.Insert(&RefreshToken{
        Token:  hex.EncodeToString(hashed[:]),
        UserID: userID,
        // ...
    })
}
```

---

## 🚨 Common Vulnerabilities

### 1. Broken Access Control (OWASP #1)

**Vulnerability**: Missing authorization checks

```javascript
// ❌ VULNERABLE
app.get('/api/users/:id', (req, res) => {
    const user = await User.findById(req.params.id);
    res.json(user);  // No authorization check!
});

// ✅ SECURE
app.get('/api/users/:id', async (req, res) => {
    const user = await User.findById(req.params.id);

    // Check authorization
    if (!ability.can('read', user)) {
        return res.status(403).send('Forbidden');
    }

    res.json(user);
});
```

### 2. Insecure Direct Object References (IDOR)

**Vulnerability**: Accessing resources by ID without authorization

```python
# ❌ VULNERABLE
@app.route('/documents/<int:doc_id>')
def get_document(doc_id):
    doc = Document.query.get(doc_id)
    return jsonify(doc)  # Anyone can access any doc!

# ✅ SECURE
@app.route('/documents/<int:doc_id>')
@login_required
def get_document(doc_id):
    doc = Document.query.get(doc_id)

    # Verify ownership or permission
    if doc.owner_id != current_user.id and \
       not current_user.has_role('admin'):
        abort(403)

    return jsonify(doc)
```

### 3. Privilege Escalation

**Vulnerability**: Users gaining elevated privileges

```go
// ❌ VULNERABLE: Accepting role from client
func updateUser(w http.ResponseWriter, r *http.Request) {
    var update UserUpdate
    json.NewDecoder(r.Body).Decode(&update)

    // Client could send {"role": "admin"}!
    user.Role = update.Role  // DANGEROUS
    db.Save(user)
}

// ✅ SECURE: Never trust client for privilege changes
func updateUser(w http.ResponseWriter, r *http.Request) {
    var update UserUpdate
    json.NewDecoder(r.Body).Decode(&update)

    // Only allow name, email changes
    user.Name = update.Name
    user.Email = update.Email
    // Role changes require separate admin endpoint

    db.Save(user)
}
```

### 4. JWT Algorithm Confusion

**Vulnerability**: Accepting "none" algorithm or switching RS256 to HS256

```go
// ❌ VULNERABLE
token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    return secretKey, nil  // No algorithm validation!
})

// ✅ SECURE
token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    // Validate expected algorithm
    if token.Method.Alg() != "RS256" {
        return nil, fmt.Errorf("unexpected algorithm: %v", token.Header["alg"])
    }
    return publicKey, nil
})
```

### 5. Mass Assignment

**Vulnerability**: Updating fields that shouldn't be modified

```ruby
# ❌ VULNERABLE
def update
  @user.update(params[:user])  # Could include is_admin: true
end

# ✅ SECURE
def update
  @user.update(user_params)
end

private
def user_params
  params.require(:user).permit(:name, :email)  # Whitelist only
end
```

---

## 🔒 Policy Security

### 1. Avoid Hardcoding

```rego
# ❌ BAD
allow {
    input.user.email == "admin@example.com"
}

# ✅ GOOD
allow {
    input.user.id in data.admin_users
}
```

### 2. Validate Policy Syntax

```bash
# Before deploying
opa check policy.rego
opa test policy.rego policy_test.rego --coverage
```

### 3. Version Control Policies

```bash
git log policies/
# Track who changed what, when, why
```

### 4. Policy Review Process

```yaml
# .github/workflows/policy-review.yml
name: Policy Review
on:
  pull_request:
    paths:
      - 'policies/**'
jobs:
  review:
    - name: Require approval
      requires: [security-team]
    - name: Run tests
      run: opa test policies/
```

---

## 🔐 Data Protection

### 1. Encrypt Sensitive Data

```go
// Encrypt policy data at rest
encryptedPolicy := encrypt(policyData, encryptionKey)
db.Store("policy", encryptedPolicy)

// Decrypt when loading
policyData := decrypt(db.Get("policy"), encryptionKey)
```

### 2. Sanitize Logs

```go
// ❌ BAD: Logging sensitive data
log.Info("Authorization check", "user", user.Email, "token", user.Token)

// ✅ GOOD: Sanitized logging
log.Info("Authorization check", "user_id", user.ID, "result", allowed)
```

### 3. Secure Database Queries

```sql
-- Use parameterized queries
SELECT * FROM users WHERE id = $1;  -- Safe

-- NOT: SELECT * FROM users WHERE id = '" + userId + "'";  -- SQL injection!
```

---

## 📊 Monitoring & Auditing

### 1. Comprehensive Audit Logging

```go
type AuditLog struct {
    Timestamp   time.Time `json:"timestamp"`
    UserID      string    `json:"user_id"`
    Action      string    `json:"action"`
    Resource    string    `json:"resource"`
    Allowed     bool      `json:"allowed"`
    Reason      string    `json:"reason"`
    IPAddress   string    `json:"ip_address"`
    UserAgent   string    `json:"user_agent"`
    RequestID   string    `json:"request_id"`
}

func logAuthzDecision(decision AuthzDecision) {
    audit.Write(AuditLog{
        Timestamp: time.Now(),
        UserID:    decision.UserID,
        Action:    decision.Action,
        Resource:  decision.Resource,
        Allowed:   decision.Allowed,
        Reason:    decision.Reason,
        IPAddress: decision.IPAddress,
        UserAgent: decision.UserAgent,
        RequestID: decision.RequestID,
    })
}
```

### 2. Alert on Suspicious Activity

```go
// Alert on multiple failures
func monitorFailedAuthorizations(userID string) {
    failures := getRecentFailures(userID, 5*time.Minute)
    if failures > 5 {
        alert.Send("Suspicious activity", fmt.Sprintf(
            "User %s has %d failed authz attempts in 5 minutes",
            userID, failures,
        ))
    }
}

// Alert on privilege escalation attempts
func detectPrivilegeEscalation(userID string) {
    if attemptedAdminAccess(userID) && !isAdmin(userID) {
        alert.Send("Privilege escalation attempt", fmt.Sprintf(
            "User %s attempted admin access without privileges",
            userID,
        ))
    }
}
```

### 3. Regular Access Reviews

```sql
-- Quarterly review of admin access
SELECT user_id, granted_at, granted_by
FROM role_assignments
WHERE role = 'admin'
  AND granted_at < NOW() - INTERVAL '90 days';
```

---

## 🚀 Production Security Checklist

### Pre-Deployment

- [ ] All authorization checks on server-side
- [ ] Default deny policy implemented
- [ ] Comprehensive tests (positive and negative cases)
- [ ] Security code review completed
- [ ] Penetration testing performed
- [ ] Audit logging implemented
- [ ] Monitoring and alerting configured
- [ ] Secrets not in code/config (use vault)
- [ ] TLS/HTTPS enforced everywhere
- [ ] Rate limiting implemented

### Post-Deployment

- [ ] Monitor audit logs daily
- [ ] Review access patterns weekly
- [ ] Conduct access reviews quarterly
- [ ] Test disaster recovery procedures
- [ ] Keep dependencies updated
- [ ] Review and update policies monthly
- [ ] Conduct security audits annually

### Incident Response

- [ ] Incident response plan documented
- [ ] Can revoke all user tokens quickly
- [ ] Can disable users immediately
- [ ] Can roll back policy changes
- [ ] Contact information for security team
- [ ] Escalation procedures defined

---

## 🔧 Framework-Specific Security

### OPA
- Validate Rego policies before deployment
- Use `opa check` and `opa test`
- Secure policy bundle server
- Sign bundles to prevent tampering

### Casbin
- Validate model files
- Store policies in secure database
- Enable watchers for multi-instance sync
- Regular policy backups

### Keycloak
- Use strong admin passwords
- Enable HTTPS only
- Regular security updates
- Secure database connection
- Configure session timeouts

### SpiceDB
- Use TLS for gRPC connections
- Secure pre-shared keys in vault
- Regular relationship backups
- Monitor permission check latency

### CASL
- Never store sensitive data in abilities
- Validate on server-side always
- Use TypeScript for type safety
- Regular dependency updates

---

## 📚 Compliance Considerations

### GDPR
- Right to access: Provide user's permissions
- Right to erasure: Delete user relationships
- Data minimization: Don't over-collect
- Consent: Track permission grants

### SOC 2
- Access control implementation
- Audit logging
- Regular access reviews
- Incident response procedures

### HIPAA
- Minimum necessary access
- Audit controls
- Access management
- Emergency access procedures

### PCI DSS
- Role-based access control
- Unique user IDs
- MFA for privileged access
- Comprehensive logging

---

## 🔗 Security Resources

### Official Guidelines
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [NIST Access Control Guidelines](https://csrc.nist.gov/projects/access-control)

### Framework Security Docs
- [OPA Security](https://www.openpolicyagent.org/docs/latest/security/)
- [Keycloak Security](https://www.keycloak.org/docs/latest/server_admin/#security)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

---

## ⚠️ Final Reminders

1. **Security is not optional** - Authorization failures lead to breaches
2. **Test thoroughly** - Include security test cases
3. **Defense in depth** - Multiple layers of controls
4. **Monitor continuously** - Watch for anomalies
5. **Update regularly** - Keep dependencies current
6. **Document everything** - Policies, procedures, incidents
7. **Train your team** - Security awareness is critical

---

**Authorization is a critical security control. Take it seriously!** 🔒
