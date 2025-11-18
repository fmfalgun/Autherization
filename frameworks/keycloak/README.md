# Keycloak

## Overview

**Keycloak** is an open-source identity and access management (IAM) solution providing both authentication and authorization. It offers complete IAM features including SSO, OAuth2, SAML, LDAP/AD integration, and fine-grained authorization.

**Website**: [keycloak.org](https://www.keycloak.org/)
**GitHub**: [github.com/keycloak/keycloak](https://github.com/keycloak/keycloak)
**License**: Apache 2.0
**Maintained By**: Red Hat

## Why Keycloak?

- **Complete IAM**: Authentication + Authorization in one
- **Standards-Based**: OAuth2, OpenID Connect, SAML 2.0
- **SSO**: Single Sign-On across applications
- **Identity Brokering**: Google, Facebook, GitHub, LDAP, AD
- **Fine-Grained Authorization**: Resource-based permissions
- **Admin UI**: Web-based management console
- **Multi-Tenancy**: Realms for tenant isolation
- **Scalable**: Clustered deployments

## Use Cases

- **Enterprise SSO**: Single sign-on for all applications
- **OAuth/SAML Provider**: Identity provider for OAuth2/SAML
- **User Management**: Centralized user directory
- **API Security**: Protect REST/GraphQL APIs
- **Multi-Tenant SaaS**: Separate realms per tenant
- **Social Login**: Integrate with social providers
- **LDAP/AD Integration**: Enterprise directory sync

## Core Concepts

### Realms
- Isolated namespace for users, roles, clients
- Each tenant can have separate realm
- Master realm for administration

### Clients
- Applications that use Keycloak
- OAuth2/OpenID Connect clients
- SAML service providers

### Users
- End users who authenticate
- Can have attributes, roles, groups

### Roles
- Realm roles: Global across realm
- Client roles: Specific to client

### Groups
- Organize users hierarchically
- Inherit roles from parent groups

### Authorization Services
- Fine-grained permissions
- Resource-based access control
- Policy-based decisions

## Quick Start

### Installation

#### Docker (Quickest)
```bash
docker run -d \
  --name keycloak \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest \
  start-dev

# Access: http://localhost:8080
# Login: admin / admin
```

#### Download & Run
```bash
# Download
wget https://github.com/keycloak/keycloak/releases/download/23.0.0/keycloak-23.0.0.zip
unzip keycloak-23.0.0.zip
cd keycloak-23.0.0

# Start
bin/kc.sh start-dev

# Access: http://localhost:8080
```

### Initial Setup

1. **Access Admin Console**: http://localhost:8080/admin
2. **Create Realm**: Click "Create Realm" (e.g., "myrealm")
3. **Create Client**: Clients → Create → Set Client ID
4. **Create User**: Users → Add user → Set credentials
5. **Assign Roles**: Users → Role mapping

## Authentication Setup

### OpenID Connect (OIDC) Client

**Create Client**:
1. Clients → Create Client
2. Client ID: `my-app`
3. Client Protocol: `openid-connect`
4. Valid Redirect URIs: `http://localhost:3000/*`
5. Web Origins: `http://localhost:3000`

**Get Configuration**:
```
http://localhost:8080/realms/myrealm/.well-known/openid-configuration
```

### Integration Example (Node.js)

```javascript
const Keycloak = require('keycloak-connect');
const session = require('express-session');
const express = require('express');

const app = express();

// Session
const memoryStore = new session.MemoryStore();
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: true,
    store: memoryStore
}));

// Keycloak config
const keycloak = new Keycloak({ store: memoryStore }, {
    realm: 'myrealm',
    'auth-server-url': 'http://localhost:8080/',
    'ssl-required': 'external',
    resource: 'my-app',
    'public-client': true
});

app.use(keycloak.middleware());

// Protected route
app.get('/protected', keycloak.protect(), (req, res) => {
    res.send('Authenticated!');
});

// Role-based protection
app.get('/admin', keycloak.protect('admin'), (req, res) => {
    res.send('Admin access');
});

app.listen(3000);
```

### Python (Flask)

```python
from flask import Flask, redirect, url_for
from flask_oidc import OpenIDConnect

app = Flask(__name__)
app.config.update({
    'SECRET_KEY': 'secret',
    'OIDC_CLIENT_SECRETS': 'client_secrets.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
})

oidc = OpenIDConnect(app)

@app.route('/')
def index():
    if oidc.user_loggedin:
        return f'Hello, {oidc.user_getfield("email")}'
    return 'Not logged in'

@app.route('/protected')
@oidc.require_login
def protected():
    return 'Protected content'

@app.route('/logout')
def logout():
    oidc.logout()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run()
```

**client_secrets.json**:
```json
{
  "web": {
    "issuer": "http://localhost:8080/realms/myrealm",
    "auth_uri": "http://localhost:8080/realms/myrealm/protocol/openid-connect/auth",
    "client_id": "my-app",
    "client_secret": "your-secret",
    "redirect_uris": ["http://localhost:5000/oidc/callback"],
    "userinfo_uri": "http://localhost:8080/realms/myrealm/protocol/openid-connect/userinfo",
    "token_uri": "http://localhost:8080/realms/myrealm/protocol/openid-connect/token"
  }
}
```

### Java (Spring Boot)

```java
// pom.xml
<dependency>
    <groupId>org.keycloak</groupId>
    <artifactId>keycloak-spring-boot-starter</artifactId>
</dependency>

// application.properties
keycloak.realm=myrealm
keycloak.auth-server-url=http://localhost:8080
keycloak.resource=my-app
keycloak.credentials.secret=your-secret
keycloak.use-resource-role-mappings=true

// SecurityConfig.java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        http.authorizeRequests()
            .antMatchers("/public/**").permitAll()
            .antMatchers("/admin/**").hasRole("admin")
            .anyRequest().authenticated();
    }
}

// Controller
@RestController
public class MyController {

    @GetMapping("/user")
    public String user(Principal principal) {
        return "Hello " + principal.getName();
    }

    @GetMapping("/admin")
    @RolesAllowed("admin")
    public String admin() {
        return "Admin panel";
    }
}
```

## Authorization Services

Keycloak's fine-grained authorization features.

### Enable Authorization

1. Clients → Select client → Settings
2. Authorization Enabled: ON
3. Save

### Resources

Define protected resources:

```json
{
  "name": "Admin Resource",
  "type": "urn:my-app:resources:admin",
  "uris": ["/admin/*"],
  "scopes": ["read", "write", "delete"]
}
```

### Scopes

Actions that can be performed:

```
- read
- write
- delete
- admin
```

### Policies

Rules to grant permissions:

#### Role-Based Policy
```json
{
  "name": "Admin Only",
  "type": "role",
  "logic": "POSITIVE",
  "roles": [
    {
      "id": "admin",
      "required": true
    }
  ]
}
```

#### User-Based Policy
```json
{
  "name": "Specific Users",
  "type": "user",
  "users": ["alice", "bob"]
}
```

#### Time-Based Policy
```json
{
  "name": "Business Hours",
  "type": "time",
  "dayMonth": "1-31",
  "month": "1-12",
  "hour": "9-17"
}
```

#### JavaScript Policy
```javascript
var context = $evaluation.getContext();
var identity = context.getIdentity();
var attributes = identity.getAttributes();

if (attributes.getValue('department').asString(0) === 'Engineering') {
    $evaluation.grant();
}
```

### Permissions

Link resources with policies:

```json
{
  "name": "Admin Permission",
  "type": "resource",
  "resources": ["Admin Resource"],
  "policies": ["Admin Only", "Business Hours"],
  "decisionStrategy": "UNANIMOUS"
}
```

### Checking Permissions (API)

```javascript
// Get access token
const token = await getAccessToken();

// Check permission
const response = await fetch(
    'http://localhost:8080/realms/myrealm/protocol/openid-connect/token',
    {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': `Bearer ${token}`
        },
        body: new URLSearchParams({
            'grant_type': 'urn:ietf:params:oauth:grant-type:uma-ticket',
            'audience': 'my-app',
            'permission': 'Admin Resource#read'
        })
    }
);

const rpt = await response.json(); // Requesting Party Token

// Decode RPT to check permissions
const permissions = decodeRPT(rpt.access_token);
```

## Admin REST API

### Create User

```bash
# Get admin token
TOKEN=$(curl -X POST 'http://localhost:8080/realms/master/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=admin' \
  -d 'password=admin' \
  -d 'grant_type=password' \
  -d 'client_id=admin-cli' \
  | jq -r '.access_token')

# Create user
curl -X POST 'http://localhost:8080/admin/realms/myrealm/users' \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "alice",
    "email": "alice@example.com",
    "enabled": true,
    "credentials": [{
      "type": "password",
      "value": "password",
      "temporary": false
    }]
  }'
```

### Assign Role

```bash
# Get user ID
USER_ID=$(curl -X GET 'http://localhost:8080/admin/realms/myrealm/users?username=alice' \
  -H "Authorization: Bearer $TOKEN" \
  | jq -r '.[0].id')

# Get role ID
ROLE_ID=$(curl -X GET 'http://localhost:8080/admin/realms/myrealm/roles/admin' \
  -H "Authorization: Bearer $TOKEN" \
  | jq -r '.id')

# Assign role
curl -X POST "http://localhost:8080/admin/realms/myrealm/users/$USER_ID/role-mappings/realm" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "[{\"id\": \"$ROLE_ID\", \"name\": \"admin\"}]"
```

## Production Deployment

### Docker Compose

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - keycloak_network

  keycloak:
    image: quay.io/keycloak/keycloak:latest
    command: start
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: password
      KC_HOSTNAME: keycloak.example.com
      KC_PROXY: edge
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: change-me
    ports:
      - "8080:8080"
    depends_on:
      - postgres
    networks:
      - keycloak_network

networks:
  keycloak_network:

volumes:
  postgres_data:
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycloak
spec:
  replicas: 2
  selector:
    matchLabels:
      app: keycloak
  template:
    metadata:
      labels:
        app: keycloak
    spec:
      containers:
      - name: keycloak
        image: quay.io/keycloak/keycloak:latest
        args: ["start"]
        env:
        - name: KC_DB
          value: "postgres"
        - name: KC_DB_URL
          value: "jdbc:postgresql://postgres:5432/keycloak"
        - name: KC_DB_USERNAME
          valueFrom:
            secretKeyRef:
              name: keycloak-db
              key: username
        - name: KC_DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: keycloak-db
              key: password
        - name: KC_HOSTNAME
          value: "keycloak.example.com"
        - name: KC_PROXY
          value: "edge"
        - name: KEYCLOAK_ADMIN
          value: "admin"
        - name: KEYCLOAK_ADMIN_PASSWORD
          valueFrom:
            secretKeyRef:
              name: keycloak-admin
              key: password
        ports:
        - containerPort: 8080
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 300
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 60
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
---
apiVersion: v1
kind: Service
metadata:
  name: keycloak
spec:
  selector:
    app: keycloak
  ports:
  - protocol: TCP
    port: 8080
    targetPort: 8080
```

## High Availability

```bash
# Start cluster mode
bin/kc.sh start \
  --db=postgres \
  --db-url=jdbc:postgresql://db:5432/keycloak \
  --cache=ispn \
  --cache-stack=kubernetes
```

## Themes Customization

### Custom Login Page

```
themes/
└── my-theme/
    ├── login/
    │   ├── theme.properties
    │   ├── login.ftl
    │   ├── resources/
    │   │   ├── css/
    │   │   │   └── login.css
    │   │   └── img/
    │   │       └── logo.png
```

**theme.properties**:
```
parent=keycloak
styles=css/login.css
```

**login.ftl** (customize HTML):
```html
<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=social.displayInfo; section>
    <!-- Custom login form -->
</@layout.registrationLayout>
```

## Event Listeners

Monitor authentication/authorization events:

```java
@Override
public void onEvent(Event event) {
    if (event.getType() == EventType.LOGIN) {
        logger.info("User {} logged in", event.getUserId());
    }
    if (event.getType() == EventType.LOGIN_ERROR) {
        logger.warn("Failed login attempt");
    }
}
```

## Best Practices

1. **Use HTTPS**: Always in production
2. **Separate Realms**: One per tenant/environment
3. **Strong Secrets**: Rotate client secrets regularly
4. **Token Expiration**: Short access tokens (5-15 min)
5. **Refresh Tokens**: Longer but revocable
6. **Database**: Use PostgreSQL/MySQL, not H2
7. **Clustering**: Multiple instances for HA
8. **Monitoring**: Enable metrics and logging
9. **Backups**: Regular realm exports
10. **Security Headers**: Enable in reverse proxy

## Performance Tuning

```bash
# Increase heap size
export JAVA_OPTS="-Xms1024m -Xmx2048m"

# Database connection pool
--db-pool-initial-size=10
--db-pool-max-size=50

# Caching
--cache-ispn-config-file=cache-ispn.xml
```

## Comparison

| Feature | Keycloak | OPA | Casbin |
|---------|----------|-----|--------|
| **IAM Complete** | ✅ | ❌ | ❌ |
| **SSO** | ✅ | ❌ | ❌ |
| **OAuth/SAML** | ✅ | ❌ | ❌ |
| **Authorization Only** | ⚠️ | ✅ | ✅ |
| **Performance** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Complexity** | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |

## Further Resources

- **Documentation**: [keycloak.org/documentation](https://www.keycloak.org/documentation)
- **Admin Guide**: [keycloak.org/docs/latest/server_admin](https://www.keycloak.org/docs/latest/server_admin/)
- **REST API**: [keycloak.org/docs-api](https://www.keycloak.org/docs-api/latest/rest-api/)
- **Blog**: [keycloak.org/blog](https://www.keycloak.org/blog)

## Community

- **Mailing List**: [lists.jboss.org/mailman/listinfo/keycloak-user](https://lists.jboss.org/mailman/listinfo/keycloak-user)
- **GitHub Discussions**: [github.com/keycloak/keycloak/discussions](https://github.com/keycloak/keycloak/discussions)
- **Stack Overflow**: Tag `keycloak`

## Next Steps

- Review [OAuth 2.0](../../fundamentals/tokens-sessions/oauth2.md)
- Understand [JWT](../../fundamentals/tokens-sessions/jwt.md)
- Compare with [OPA](../opa/README.md) and [Casbin](../casbin/README.md)
- Check [Comparative Analysis](../../COMPARISON.md)
