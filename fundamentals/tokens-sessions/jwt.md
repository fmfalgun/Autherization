# JWT (JSON Web Tokens)

## Overview

**JWT** (RFC 7519) is a compact, URL-safe token format for securely transmitting information between parties as a JSON object. Commonly used for authorization in stateless APIs.

## Structure

JWT consists of three parts separated by dots:

```
header.payload.signature
```

### Example JWT

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### Decoded

**Header**:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload**:
```json
{
  "sub": "1234567890",
  "name": "Alice",
  "role": "admin",
  "iat": 1516239022
}
```

**Signature**:
```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret
)
```

## Claims

### Registered Claims (RFC standard)

- **iss** (issuer): Who issued the token
- **sub** (subject): User identifier
- **aud** (audience): Who the token is for
- **exp** (expiration): When token expires (Unix timestamp)
- **nbf** (not before): Token not valid before this time
- **iat** (issued at): When token was issued
- **jti** (JWT ID): Unique identifier

### Custom Claims

```json
{
  "sub": "user-123",
  "email": "alice@example.com",
  "role": "admin",
  "permissions": ["read", "write", "delete"],
  "department": "engineering",
  "iat": 1700000000,
  "exp": 1700003600
}
```

## Signing Algorithms

### Symmetric (Shared Secret)

- **HS256**: HMAC with SHA-256
- **HS384**: HMAC with SHA-384
- **HS512**: HMAC with SHA-512

**Pros**: Fast, simple
**Cons**: Same secret for sign and verify

### Asymmetric (Public/Private Key)

- **RS256**: RSA with SHA-256
- **RS384**: RSA with SHA-384
- **RS512**: RSA with SHA-512
- **ES256**: ECDSA with SHA-256

**Pros**: Public key for verification, private key kept secret
**Cons**: Slower, more complex

## Usage in Authorization

### Access Token

```json
{
  "sub": "user-123",
  "email": "alice@example.com",
  "role": "admin",
  "permissions": ["documents:read", "documents:write"],
  "iat": 1700000000,
  "exp": 1700003600
}
```

### API Request

```http
GET /api/documents HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Implementation Examples

### Go

```go
package main

import (
    "fmt"
    "time"
    "github.com/golang-jwt/jwt/v5"
)

type Claims struct {
    Email       string   `json:"email"`
    Role        string   `json:"role"`
    Permissions []string `json:"permissions"`
    jwt.RegisteredClaims
}

// Generate JWT
func generateToken(userID, email, role string, permissions []string) (string, error) {
    claims := Claims{
        Email:       email,
        Role:        role,
        Permissions: permissions,
        RegisteredClaims: jwt.RegisteredClaims{
            Subject:   userID,
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            Issuer:    "auth.example.com",
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte("your-secret-key"))
}

// Verify JWT
func verifyToken(tokenString string) (*Claims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        return []byte("your-secret-key"), nil
    })

    if err != nil {
        return nil, err
    }

    if claims, ok := token.Claims.(*Claims); ok && token.Valid {
        return claims, nil
    }

    return nil, fmt.Errorf("invalid token")
}

func main() {
    // Generate
    token, _ := generateToken("user-123", "alice@example.com", "admin", []string{"read", "write"})
    fmt.Println("Token:", token)

    // Verify
    claims, _ := verifyToken(token)
    fmt.Printf("User: %s, Role: %s\n", claims.Email, claims.Role)
}
```

## Security Best Practices

### 1. Use Strong Secrets

```go
// BAD
secret := "secret"

// GOOD
secret := generateRandomString(32) // 256 bits
```

### 2. Short Expiration

```json
{
  "exp": 1700003600  // 15-60 minutes recommended
}
```

### 3. Validate All Claims

```go
func validateToken(claims *Claims) error {
    // Check expiration
    if time.Now().Unix() > claims.ExpiresAt.Unix() {
        return errors.New("token expired")
    }

    // Check audience
    if claims.Audience[0] != "api.example.com" {
        return errors.New("invalid audience")
    }

    // Check issuer
    if claims.Issuer != "auth.example.com" {
        return errors.New("invalid issuer")
    }

    return nil
}
```

### 4. Don't Store Sensitive Data

```json
// BAD
{
  "sub": "user-123",
  "password": "secret",
  "ssn": "123-45-6789"
}

// GOOD
{
  "sub": "user-123",
  "role": "user"
}
```

### 5. Use HTTPS Only

Never transmit JWTs over HTTP.

### 6. Validate Algorithm

```go
token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    // Validate algorithm
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    }
    return []byte("secret"), nil
})
```

## Common Vulnerabilities

### 1. None Algorithm Attack

Attacker sets `alg: "none"` to bypass signature verification.

**Prevention**:
```go
// Always validate algorithm
if token.Method.Alg() == "none" {
    return errors.New("none algorithm not allowed")
}
```

### 2. Algorithm Confusion (RS256 → HS256)

Attacker changes RS256 to HS256 and signs with public key.

**Prevention**:
```go
// Explicitly specify expected algorithm
expectedAlg := jwt.SigningMethodRS256
if token.Method != expectedAlg {
    return errors.New("unexpected algorithm")
}
```

### 3. Weak Secret

**Prevention**: Use strong, random secrets (>256 bits)

## JWT vs Session Tokens

| Aspect | JWT | Session |
|--------|-----|---------|
| **Storage** | Client-side | Server-side |
| **Stateless** | Yes | No |
| **Scalability** | High | Medium |
| **Revocation** | Hard | Easy |
| **Size** | Large | Small |
| **Best For** | APIs, microservices | Traditional web apps |

## Middleware Example

```go
func JWTMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Extract token from header
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        tokenString := strings.TrimPrefix(authHeader, "Bearer ")

        // Verify token
        claims, err := verifyToken(tokenString)
        if err != nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Add claims to context
        ctx := context.WithValue(r.Context(), "claims", claims)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// Protected endpoint
func protectedHandler(w http.ResponseWriter, r *http.Request) {
    claims := r.Context().Value("claims").(*Claims)
    fmt.Fprintf(w, "Hello, %s!", claims.Email)
}
```

## Refresh Tokens

Access token (JWT) + Refresh token pattern:

```go
type TokenPair struct {
    AccessToken  string `json:"access_token"`   // Short-lived JWT (15 min)
    RefreshToken string `json:"refresh_token"`  // Long-lived (7 days)
}

// Store refresh tokens in database
type RefreshToken struct {
    Token     string
    UserID    string
    ExpiresAt time.Time
    Revoked   bool
}
```

## Further Reading

- [RFC 7519: JWT](https://datatracker.ietf.org/doc/html/rfc7519)
- [JWT.io](https://jwt.io/)
- [JWT Security Best Practices](https://tools.ietf.org/html/rfc8725)

## Next Steps

- Learn [OAuth 2.0](./oauth2.md)
- Understand [Token Management](./tokens.md)
- Explore [Session Management](./session-management.md)
