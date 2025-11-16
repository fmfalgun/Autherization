# Token Management

## Overview

Token management encompasses the lifecycle of tokens from creation to revocation, including storage, validation, rotation, and security practices.

## Token Types

### 1. Access Tokens
- **Purpose**: API access
- **Lifetime**: Short (15-60 minutes)
- **Format**: JWT or opaque
- **Storage**: Memory only

### 2. Refresh Tokens
- **Purpose**: Obtain new access tokens
- **Lifetime**: Long (days to months)
- **Format**: Opaque (random string)
- **Storage**: Secure database + HttpOnly cookie

### 3. ID Tokens
- **Purpose**: User identity (OpenID Connect)
- **Lifetime**: Short
- **Format**: JWT
- **Storage**: Not needed after validation

### 4. API Keys
- **Purpose**: Application identification
- **Lifetime**: Long or no expiration
- **Format**: Random string
- **Storage**: Secure vault

## Token Lifecycle

```
1. Creation/Issuance
   ↓
2. Distribution (to client)
   ↓
3. Storage (client-side)
   ↓
4. Usage (API requests)
   ↓
5. Validation (server-side)
   ↓
6. Refresh (optional)
   ↓
7. Revocation/Expiration
```

## Token Creation

### Secure Token Generation

```go
package main

import (
    "crypto/rand"
    "encoding/base64"
)

// Generate cryptographically secure random token
func generateToken(length int) (string, error) {
    bytes := make([]byte, length)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(bytes), nil
}

// Generate refresh token
func generateRefreshToken() (string, error) {
    return generateToken(32) // 256 bits
}
```

### Token Structure (JWT)

```go
type TokenClaims struct {
    UserID      string   `json:"sub"`
    Email       string   `json:"email"`
    Role        string   `json:"role"`
    Permissions []string `json:"permissions"`
    TokenID     string   `json:"jti"`
    IssuedAt    int64    `json:"iat"`
    ExpiresAt   int64    `json:"exp"`
}
```

## Token Storage

### Client-Side Storage Options

| Storage | Security | XSS Vulnerable | CSRF Vulnerable | Best For |
|---------|----------|----------------|-----------------|----------|
| **localStorage** | Low | Yes | No | Never use for tokens |
| **sessionStorage** | Low | Yes | No | Never use for tokens |
| **Memory** | High | No | No | Access tokens (SPA) |
| **HttpOnly Cookie** | High | No | Yes (mitigated with SameSite) | Refresh tokens |

### Recommended Pattern

```javascript
// Access token: In-memory only
let accessToken = null;

async function setAccessToken(token) {
    accessToken = token;
    // Never persist to localStorage!
}

// Refresh token: HttpOnly cookie (set by server)
// Not accessible to JavaScript
```

### Server-Side Storage

```go
type RefreshToken struct {
    ID        string    `db:"id"`
    UserID    string    `db:"user_id"`
    Token     string    `db:"token"`
    ExpiresAt time.Time `db:"expires_at"`
    Revoked   bool      `db:"revoked"`
    CreatedAt time.Time `db:"created_at"`
    LastUsed  time.Time `db:"last_used"`
}

// Store refresh token
func (s *TokenStore) StoreRefreshToken(userID, token string, expiresAt time.Time) error {
    rt := &RefreshToken{
        ID:        uuid.New().String(),
        UserID:    userID,
        Token:     hashToken(token), // Store hashed
        ExpiresAt: expiresAt,
        CreatedAt: time.Now(),
    }
    return s.db.Insert(rt)
}
```

## Token Validation

### Access Token Validation

```go
func validateAccessToken(tokenString string) (*Claims, error) {
    // 1. Parse token
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, keyFunc)
    if err != nil {
        return nil, err
    }

    // 2. Verify signature
    if !token.Valid {
        return nil, errors.New("invalid signature")
    }

    claims, ok := token.Claims.(*Claims)
    if !ok {
        return nil, errors.New("invalid claims")
    }

    // 3. Check expiration
    if time.Now().Unix() > claims.ExpiresAt {
        return nil, errors.New("token expired")
    }

    // 4. Check issuer
    if claims.Issuer != expectedIssuer {
        return nil, errors.New("invalid issuer")
    }

    // 5. Check audience
    if !contains(claims.Audience, expectedAudience) {
        return nil, errors.New("invalid audience")
    }

    // 6. Check revocation (if using blacklist)
    if isRevoked(claims.TokenID) {
        return nil, errors.New("token revoked")
    }

    return claims, nil
}
```

### Refresh Token Validation

```go
func validateRefreshToken(token string) (*RefreshToken, error) {
    // 1. Hash incoming token
    hashedToken := hashToken(token)

    // 2. Look up in database
    rt, err := db.FindRefreshToken(hashedToken)
    if err != nil {
        return nil, errors.New("invalid token")
    }

    // 3. Check expiration
    if time.Now().After(rt.ExpiresAt) {
        return nil, errors.New("token expired")
    }

    // 4. Check if revoked
    if rt.Revoked {
        return nil, errors.New("token revoked")
    }

    // 5. Update last used
    db.UpdateLastUsed(rt.ID, time.Now())

    return rt, nil
}
```

## Token Rotation

### Refresh Token Rotation

```go
func rotateRefreshToken(oldToken string) (*TokenPair, error) {
    // 1. Validate old token
    rt, err := validateRefreshToken(oldToken)
    if err != nil {
        return nil, err
    }

    // 2. Revoke old token
    db.RevokeRefreshToken(rt.ID)

    // 3. Generate new tokens
    accessToken := generateAccessToken(rt.UserID)
    newRefreshToken := generateRefreshToken()

    // 4. Store new refresh token
    storeRefreshToken(rt.UserID, newRefreshToken)

    return &TokenPair{
        AccessToken:  accessToken,
        RefreshToken: newRefreshToken,
    }, nil
}
```

### Access Token Rotation

```go
// Automatic rotation before expiration
func autoRefreshAccessToken() {
    ticker := time.NewTicker(45 * time.Minute) // Refresh every 45 min
    for range ticker.C {
        newAccessToken, err := refreshAccessToken()
        if err != nil {
            log.Error("Failed to refresh access token")
            continue
        }
        setAccessToken(newAccessToken)
    }
}
```

## Token Revocation

### Approaches

#### 1. Blacklist (for JWTs)

```go
type TokenBlacklist struct {
    sync.RWMutex
    tokens map[string]time.Time
}

func (b *TokenBlacklist) Revoke(tokenID string, expiresAt time.Time) {
    b.Lock()
    defer b.Unlock()
    b.tokens[tokenID] = expiresAt
}

func (b *TokenBlacklist) IsRevoked(tokenID string) bool {
    b.RLock()
    defer b.RUnlock()

    expiresAt, exists := b.tokens[tokenID]
    if !exists {
        return false
    }

    // Remove expired entries
    if time.Now().After(expiresAt) {
        delete(b.tokens, tokenID)
        return false
    }

    return true
}
```

#### 2. Database Revocation (for refresh tokens)

```sql
UPDATE refresh_tokens
SET revoked = true, revoked_at = NOW()
WHERE user_id = $1;  -- Revoke all user's tokens
```

#### 3. Revocation Events

```go
type RevocationEvent struct {
    TokenID   string
    RevokedAt time.Time
    Reason    string
}

func publishRevocation(event RevocationEvent) {
    // Publish to message queue
    messageQueue.Publish("token.revoked", event)
}

// Subscribers update local blacklists
func subscribeRevocations() {
    messageQueue.Subscribe("token.revoked", func(event RevocationEvent) {
        localBlacklist.Add(event.TokenID, event.RevokedAt)
    })
}
```

## Security Best Practices

### 1. Token Entropy

```go
// Minimum 128 bits of entropy
func generateSecureToken() string {
    bytes := make([]byte, 32) // 256 bits
    rand.Read(bytes)
    return base64.URLEncoding.EncodeToString(bytes)
}
```

### 2. Rate Limiting

```go
func tokenRefreshRateLimiter(userID string) error {
    key := "refresh:" + userID
    count := redis.Incr(key)
    redis.Expire(key, 1*time.Hour)

    if count > 5 { // Max 5 refreshes per hour
        return errors.New("rate limit exceeded")
    }
    return nil
}
```

### 3. Audit Logging

```go
type TokenEvent struct {
    EventType string    `json:"event_type"` // issued, refreshed, revoked
    UserID    string    `json:"user_id"`
    TokenID   string    `json:"token_id"`
    IPAddress string    `json:"ip_address"`
    UserAgent string    `json:"user_agent"`
    Timestamp time.Time `json:"timestamp"`
}

func logTokenEvent(event TokenEvent) {
    auditLog.Write(event)
}
```

### 4. Bind Tokens to Client

```go
// Include client fingerprint in token
type Claims struct {
    UserID          string `json:"sub"`
    ClientFingerprint string `json:"cfp"` // Hash of IP + User-Agent
    jwt.RegisteredClaims
}

func validateClientBinding(claims *Claims, request *http.Request) error {
    currentFingerprint := generateFingerprint(request)
    if claims.ClientFingerprint != currentFingerprint {
        return errors.New("token binding mismatch")
    }
    return nil
}
```

## Monitoring and Alerts

```go
// Alert on suspicious activity
func monitorTokenUsage(event TokenEvent) {
    // Multiple refreshes in short time
    if detectRapidRefresh(event.UserID) {
        alertSecurityTeam("Rapid token refresh detected", event)
    }

    // Login from new location
    if isNewLocation(event.UserID, event.IPAddress) {
        alertUser("New login location detected", event)
    }

    // Concurrent token usage
    if detectConcurrentUse(event.TokenID) {
        revokeAllTokens(event.UserID)
        alertSecurityTeam("Concurrent token use - possible theft", event)
    }
}
```

## Token Formats

### Opaque Tokens

```
// Random, unreadable
7Hj9K2mN4pQrS5tVwXyZ1aB3cD6eF8gH
```

**Pros**: Cannot be decoded, smaller
**Cons**: Require server lookup

### JWTs

```
eyJhbGc...  // Can be decoded
```

**Pros**: Self-contained, no server lookup
**Cons**: Larger, hard to revoke

### Choosing Between Them

| Use Case | Recommendation |
|----------|----------------|
| Internal microservices | JWT |
| External API | JWT |
| Mobile app | JWT + opaque refresh token |
| Web app (session-based) | Opaque |
| High security | Opaque (easier revocation) |

## Further Reading

- [RFC 6750: Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)
- [OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)

## Next Steps

- Learn [JWT](./jwt.md)
- Understand [OAuth 2.0](./oauth2.md)
- Explore [Session Management](./session-management.md)
