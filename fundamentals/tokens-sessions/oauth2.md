# OAuth 2.0

## Overview

**OAuth 2.0** is an authorization framework (RFC 6749) that enables applications to obtain limited access to user accounts on an HTTP service. It's the industry-standard protocol for authorization.

## Key Distinction

**OAuth 2.0 is for AUTHORIZATION, not authentication:**
- **Authorization**: What can you access?
- **Authentication**: Who are you? (use OpenID Connect)

## Core Concepts

### Roles

1. **Resource Owner**: User who owns the data
2. **Client**: Application requesting access
3. **Authorization Server**: Issues access tokens
4. **Resource Server**: Hosts protected resources

### Tokens

- **Access Token**: Short-lived token for API access
- **Refresh Token**: Long-lived token to get new access tokens
- **Scope**: Permissions granted to the access token

## Grant Types

### 1. Authorization Code Grant

Most secure, used for server-side applications.

**Flow**:
```
1. Client → User: Redirect to authorization server
2. User → AuthZ Server: Login and consent
3. AuthZ Server → Client: Authorization code
4. Client → AuthZ Server: Exchange code for token
5. AuthZ Server → Client: Access token + refresh token
6. Client → Resource Server: API call with access token
```

**Example**:
```http
# Step 1: Authorization request
GET /authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=https://app.example.com/callback&
  scope=read:documents write:documents&
  state=random_state_string
Host: authorization-server.com

# Step 3: Authorization code returned
https://app.example.com/callback?code=AUTH_CODE&state=random_state_string

# Step 4: Token request
POST /token
Host: authorization-server.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTH_CODE&
redirect_uri=https://app.example.com/callback&
client_id=CLIENT_ID&
client_secret=CLIENT_SECRET

# Step 5: Token response
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "tGzv3JOk...",
  "scope": "read:documents write:documents"
}
```

### 2. Client Credentials Grant

For machine-to-machine communication.

**Flow**:
```
1. Client → AuthZ Server: Client credentials
2. AuthZ Server → Client: Access token
3. Client → Resource Server: API call with token
```

**Example**:
```http
POST /token
Host: authorization-server.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&
client_id=CLIENT_ID&
client_secret=CLIENT_SECRET&
scope=read:api

# Response
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### 3. Refresh Token Grant

Get new access token without user interaction.

```http
POST /token
Host: authorization-server.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=tGzv3JOk...&
client_id=CLIENT_ID&
client_secret=CLIENT_SECRET

# Response
{
  "access_token": "new_access_token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "new_refresh_token"
}
```

## Scopes

Define permissions requested by the client.

```json
{
  "scopes": {
    "read:documents": "Read your documents",
    "write:documents": "Create and modify documents",
    "delete:documents": "Delete documents",
    "read:profile": "Read your profile",
    "admin:users": "Manage users"
  }
}
```

**Usage**:
```http
GET /authorize?
  response_type=code&
  client_id=CLIENT_ID&
  scope=read:documents write:documents&
  redirect_uri=https://app.example.com/callback
```

## Security Best Practices

### 1. Use PKCE (RFC 7636)

Proof Key for Code Exchange - prevents authorization code interception.

```
1. Client generates code_verifier (random string)
2. Client creates code_challenge = SHA256(code_verifier)
3. Authorization request includes code_challenge
4. Token request includes code_verifier
5. Server verifies: SHA256(code_verifier) == code_challenge
```

**Example**:
```http
# Authorization request with PKCE
GET /authorize?
  response_type=code&
  client_id=CLIENT_ID&
  code_challenge=CHALLENGE&
  code_challenge_method=S256&
  redirect_uri=https://app.example.com/callback

# Token request with PKCE
POST /token
grant_type=authorization_code&
code=AUTH_CODE&
code_verifier=VERIFIER&
client_id=CLIENT_ID
```

### 2. Validate Redirect URIs

Always validate redirect_uri matches registered URIs.

### 3. Use State Parameter

Prevent CSRF attacks.

```http
GET /authorize?
  response_type=code&
  state=random_csrf_token&
  client_id=CLIENT_ID
```

### 4. Short-Lived Access Tokens

Recommended: 15 minutes to 1 hour

### 5. Secure Storage

- **Access tokens**: Memory only, never localStorage
- **Refresh tokens**: HttpOnly cookies or secure storage

## Implementation Example (Go)

```go
package main

import (
    "context"
    "fmt"
    "golang.org/x/oauth2"
)

func main() {
    conf := &oauth2.Config{
        ClientID:     "CLIENT_ID",
        ClientSecret: "CLIENT_SECRET",
        Scopes:       []string{"read:documents", "write:documents"},
        Endpoint: oauth2.Endpoint{
            AuthURL:  "https://auth.example.com/authorize",
            TokenURL: "https://auth.example.com/token",
        },
        RedirectURL: "https://app.example.com/callback",
    }

    // Generate authorization URL
    url := conf.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
    fmt.Printf("Visit: %v\n", url)

    // Exchange code for token
    code := "authorization-code-from-callback"
    token, err := conf.Exchange(context.Background(), code)
    if err != nil {
        panic(err)
    }

    // Use token
    client := conf.Client(context.Background(), token)
    resp, _ := client.Get("https://api.example.com/documents")
    defer resp.Body.Close()
}
```

## Further Reading

- [RFC 6749: OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [PKCE (RFC 7636)](https://datatracker.ietf.org/doc/html/rfc7636)

## Next Steps

- Learn [JWT](./jwt.md) for token format
- Understand [Token Management](./tokens.md)
- Explore [Keycloak](../../frameworks/keycloak/) for OAuth implementation
