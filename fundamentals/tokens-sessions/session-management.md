# Session Management

## Overview

**Session management** tracks user state across multiple requests in stateful applications. While modern APIs often use stateless tokens (JWT), sessions remain important for traditional web applications and certain security scenarios.

## Session vs Token-Based Auth

| Aspect | Sessions | Tokens (JWT) |
|--------|----------|--------------|
| **State** | Server-side | Stateless |
| **Storage** | Server memory/DB | Client-side |
| **Scalability** | Harder | Easier |
| **Revocation** | Easy | Hard |
| **Size** | Small (ID only) | Large (data + signature) |
| **Best For** | Web apps | APIs, SPAs, mobile |

## Session Lifecycle

```
1. User Login
   ↓
2. Create Session (server)
   ↓
3. Generate Session ID
   ↓
4. Store Session Data
   ↓
5. Send Session ID to Client (cookie)
   ↓
6. Client sends Session ID with each request
   ↓
7. Server validates Session ID
   ↓
8. Access granted/denied
   ↓
9. Session timeout or logout
```

## Implementation

### Basic Session Store

```go
package main

import (
    "crypto/rand"
    "encoding/base64"
    "errors"
    "sync"
    "time"
)

type Session struct {
    ID        string
    UserID    string
    Data      map[string]interface{}
    CreatedAt time.Time
    ExpiresAt time.Time
    LastSeen  time.Time
}

type SessionStore struct {
    mu       sync.RWMutex
    sessions map[string]*Session
}

func NewSessionStore() *SessionStore {
    return &SessionStore{
        sessions: make(map[string]*Session),
    }
}

// Generate secure session ID
func generateSessionID() (string, error) {
    bytes := make([]byte, 32)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(bytes), nil
}

// Create new session
func (s *SessionStore) Create(userID string, lifetime time.Duration) (*Session, error) {
    sessionID, err := generateSessionID()
    if err != nil {
        return nil, err
    }

    session := &Session{
        ID:        sessionID,
        UserID:    userID,
        Data:      make(map[string]interface{}),
        CreatedAt: time.Now(),
        ExpiresAt: time.Now().Add(lifetime),
        LastSeen:  time.Now(),
    }

    s.mu.Lock()
    s.sessions[sessionID] = session
    s.mu.Unlock()

    return session, nil
}

// Get session
func (s *SessionStore) Get(sessionID string) (*Session, error) {
    s.mu.RLock()
    session, exists := s.sessions[sessionID]
    s.mu.RUnlock()

    if !exists {
        return nil, errors.New("session not found")
    }

    if time.Now().After(session.ExpiresAt) {
        s.Delete(sessionID)
        return nil, errors.New("session expired")
    }

    // Update last seen
    s.mu.Lock()
    session.LastSeen = time.Now()
    s.mu.Unlock()

    return session, nil
}

// Delete session
func (s *SessionStore) Delete(sessionID string) {
    s.mu.Lock()
    delete(s.sessions, sessionID)
    s.mu.Unlock()
}

// Clean up expired sessions
func (s *SessionStore) CleanupExpired() {
    s.mu.Lock()
    defer s.mu.Unlock()

    for id, session := range s.sessions {
        if time.Now().After(session.ExpiresAt) {
            delete(s.sessions, id)
        }
    }
}
```

### Redis-Based Session Store

```go
package main

import (
    "context"
    "encoding/json"
    "time"

    "github.com/go-redis/redis/v8"
)

type RedisSessionStore struct {
    client *redis.Client
}

func NewRedisSessionStore(addr string) *RedisSessionStore {
    return &RedisSessionStore{
        client: redis.NewClient(&redis.Options{
            Addr: addr,
        }),
    }
}

func (s *RedisSessionStore) Create(ctx context.Context, userID string, lifetime time.Duration) (string, error) {
    sessionID, _ := generateSessionID()

    session := &Session{
        ID:        sessionID,
        UserID:    userID,
        Data:      make(map[string]interface{}),
        CreatedAt: time.Now(),
        ExpiresAt: time.Now().Add(lifetime),
    }

    data, _ := json.Marshal(session)

    // Store with automatic expiration
    err := s.client.Set(ctx, "session:"+sessionID, data, lifetime).Err()
    if err != nil {
        return "", err
    }

    return sessionID, nil
}

func (s *RedisSessionStore) Get(ctx context.Context, sessionID string) (*Session, error) {
    data, err := s.client.Get(ctx, "session:"+sessionID).Bytes()
    if err == redis.Nil {
        return nil, errors.New("session not found")
    } else if err != nil {
        return nil, err
    }

    var session Session
    if err := json.Unmarshal(data, &session); err != nil {
        return nil, err
    }

    return &session, nil
}

func (s *RedisSessionStore) Delete(ctx context.Context, sessionID string) error {
    return s.client.Del(ctx, "session:"+sessionID).Err()
}
```

## HTTP Middleware

```go
func SessionMiddleware(store *SessionStore) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Get session ID from cookie
            cookie, err := r.Cookie("session_id")
            if err != nil {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            // Validate session
            session, err := store.Get(cookie.Value)
            if err != nil {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            // Add session to context
            ctx := context.WithValue(r.Context(), "session", session)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

// Login handler
func loginHandler(w http.ResponseWriter, r *http.Request, store *SessionStore) {
    // Authenticate user (omitted)
    userID := "user-123"

    // Create session
    session, err := store.Create(userID, 24*time.Hour)
    if err != nil {
        http.Error(w, "Internal error", http.StatusInternalServerError)
        return
    }

    // Set secure cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "session_id",
        Value:    session.ID,
        HttpOnly: true,    // Prevent JavaScript access
        Secure:   true,    // HTTPS only
        SameSite: http.SameSiteStrictMode,
        MaxAge:   86400,   // 24 hours
        Path:     "/",
    })

    w.Write([]byte("Logged in"))
}

// Logout handler
func logoutHandler(w http.ResponseWriter, r *http.Request, store *SessionStore) {
    cookie, err := r.Cookie("session_id")
    if err == nil {
        store.Delete(cookie.Value)
    }

    // Clear cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "session_id",
        Value:    "",
        HttpOnly: true,
        Secure:   true,
        MaxAge:   -1, // Delete cookie
        Path:     "/",
    })

    w.Write([]byte("Logged out"))
}
```

## Security Best Practices

### 1. Secure Session ID

```go
// Generate cryptographically secure session ID
func generateSessionID() (string, error) {
    // Minimum 128 bits of entropy
    bytes := make([]byte, 32) // 256 bits
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(bytes), nil
}
```

### 2. Secure Cookie Attributes

```go
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    HttpOnly: true,                      // XSS protection
    Secure:   true,                      // HTTPS only
    SameSite: http.SameSiteStrictMode,   // CSRF protection
    MaxAge:   3600,
    Path:     "/",
    Domain:   ".example.com",            // Limit scope
})
```

### 3. Session Regeneration

```go
// Regenerate session ID after privilege escalation
func regenerateSession(store *SessionStore, oldSessionID string) (string, error) {
    // Get old session
    oldSession, err := store.Get(oldSessionID)
    if err != nil {
        return "", err
    }

    // Create new session with same data
    newSession, err := store.Create(oldSession.UserID, 24*time.Hour)
    if err != nil {
        return "", err
    }

    // Copy data
    newSession.Data = oldSession.Data

    // Delete old session
    store.Delete(oldSessionID)

    return newSession.ID, nil
}
```

### 4. Absolute and Idle Timeouts

```go
type Session struct {
    ID              string
    UserID          string
    CreatedAt       time.Time
    LastActivityAt  time.Time
    AbsoluteTimeout time.Duration
    IdleTimeout     time.Duration
}

func (s *Session) IsExpired() bool {
    now := time.Now()

    // Check absolute timeout (max session lifetime)
    if now.Sub(s.CreatedAt) > s.AbsoluteTimeout {
        return true
    }

    // Check idle timeout (max inactivity)
    if now.Sub(s.LastActivityAt) > s.IdleTimeout {
        return true
    }

    return false
}
```

### 5. IP Address Binding

```go
type Session struct {
    ID        string
    UserID    string
    IPAddress string
}

func validateSessionIP(session *Session, requestIP string) error {
    if session.IPAddress != requestIP {
        return errors.New("session IP mismatch")
    }
    return nil
}
```

## Session Fixation Prevention

```go
// Before login: anonymous session
sessionID := "old-session-id"

// After login: regenerate session ID
func login(w http.ResponseWriter, r *http.Request) {
    // Authenticate user
    userID := authenticateUser(r)

    // Destroy old session
    oldCookie, _ := r.Cookie("session_id")
    if oldCookie != nil {
        sessionStore.Delete(oldCookie.Value)
    }

    // Create new session
    newSession, _ := sessionStore.Create(userID, 24*time.Hour)

    // Set new cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "session_id",
        Value:    newSession.ID,
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteStrictMode,
    })
}
```

## Concurrent Session Management

```go
type SessionStore struct {
    sessions map[string][]*Session  // userID -> sessions
    mu       sync.RWMutex
}

// Limit concurrent sessions per user
func (s *SessionStore) Create(userID string, maxSessions int) (*Session, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    userSessions := s.sessions[userID]

    // Enforce limit
    if len(userSessions) >= maxSessions {
        // Remove oldest session
        s.removeOldestSession(userID)
    }

    // Create new session
    session := &Session{
        ID:        generateSessionID(),
        UserID:    userID,
        CreatedAt: time.Now(),
    }

    s.sessions[userID] = append(s.sessions[userID], session)
    return session, nil
}

// List all user sessions
func (s *SessionStore) ListUserSessions(userID string) []*Session {
    s.mu.RLock()
    defer s.mu.RUnlock()
    return s.sessions[userID]
}

// Revoke specific session
func (s *SessionStore) RevokeSession(userID, sessionID string) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    userSessions := s.sessions[userID]
    for i, session := range userSessions {
        if session.ID == sessionID {
            s.sessions[userID] = append(userSessions[:i], userSessions[i+1:]...)
            return nil
        }
    }
    return errors.New("session not found")
}

// Revoke all user sessions (force logout)
func (s *SessionStore) RevokeAllSessions(userID string) {
    s.mu.Lock()
    defer s.mu.Unlock()
    delete(s.sessions, userID)
}
```

## Monitoring and Alerts

```go
type SessionEvent struct {
    EventType string    `json:"event_type"` // created, accessed, expired
    SessionID string    `json:"session_id"`
    UserID    string    `json:"user_id"`
    IPAddress string    `json:"ip_address"`
    UserAgent string    `json:"user_agent"`
    Timestamp time.Time `json:"timestamp"`
}

func monitorSessionActivity(event SessionEvent) {
    // Alert on multiple failed session validations
    if detectBruteForce(event.UserID) {
        alertSecurityTeam("Possible session hijacking attempt", event)
    }

    // Alert on session from new location
    if isNewLocation(event.UserID, event.IPAddress) {
        notifyUser("New session from unusual location", event)
    }
}
```

## Distributed Sessions

### Using Redis Cluster

```go
import "github.com/go-redis/redis/v8"

func NewRedisClusterSessionStore(addrs []string) *RedisSessionStore {
    client := redis.NewClusterClient(&redis.ClusterOptions{
        Addrs: addrs,
    })

    return &RedisSessionStore{client: client}
}
```

### Session Replication

```go
// Replicate session across multiple stores
type ReplicatedSessionStore struct {
    primary   SessionStore
    replicas  []SessionStore
}

func (s *ReplicatedSessionStore) Create(userID string) (*Session, error) {
    // Write to primary
    session, err := s.primary.Create(userID)
    if err != nil {
        return nil, err
    }

    // Async replication to replicas
    go func() {
        for _, replica := range s.replicas {
            replica.Store(session)
        }
    }()

    return session, nil
}
```

## Further Reading

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [RFC 6265: HTTP State Management (Cookies)](https://datatracker.ietf.org/doc/html/rfc6265)

## Next Steps

- Learn [JWT](./jwt.md) for stateless alternative
- Understand [OAuth 2.0](./oauth2.md)
- Explore [Token Management](./tokens.md)
- Review [Zero Trust](../concepts/zero-trust.md) principles
