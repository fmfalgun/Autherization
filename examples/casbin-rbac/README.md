# Casbin RBAC Example

A complete web application demonstrating RBAC (Role-Based Access Control) using Casbin.

## Overview

This example demonstrates:
- RBAC with Casbin in Go
- RESTful API with authorization middleware
- Role hierarchies and inheritance
- Dynamic policy management
- Web-based admin interface

## Architecture

```
┌──────────────┐
│    Client    │
│  (Browser/   │
│   Postman)   │
└──────┬───────┘
       │ HTTP
       ▼
┌──────────────┐
│ Go Web Server│
│  (port 8080) │
├──────────────┤
│   Casbin     │
│  Middleware  │
├──────────────┤
│ Model+Policy │
└──────────────┘
```

## Files

- `main.go` - Web server with Casbin middleware
- `model.conf` - RBAC model definition
- `policy.csv` - Permissions and role assignments
- `handlers.go` - API endpoint handlers
- `middleware.go` - Authorization middleware
- `docker-compose.yml` - Docker setup
- `Dockerfile` - Go application container
- `Makefile` - Common commands

## Quick Start

### Prerequisites

- Go 1.21+ or Docker
- Make (optional)

### Option 1: Run with Docker

```bash
# Build and start
docker-compose up --build

# Server will be available at http://localhost:8080
```

### Option 2: Run Locally

```bash
# Install dependencies
go mod download

# Run server
go run .

# Server will start on http://localhost:8080
```

## RBAC Model

### Roles

- **admin** - Full access to all resources
- **manager** - Can manage their department's resources
- **user** - Can read public resources and manage their own

### Role Hierarchy

```
admin (inherits all permissions)
  └── manager (inherits user permissions)
        └── user (basic permissions)
```

## API Endpoints

### Public Endpoints (No Auth Required)

```bash
# Health check
GET /health

# Get all users
GET /api/users
```

### Protected Endpoints

```bash
# View documents (user, manager, admin)
GET /api/documents

# Create document (manager, admin)
POST /api/documents

# Update document (manager, admin)
PUT /api/documents/:id

# Delete document (admin only)
DELETE /api/documents/:id

# Manage users (admin only)
POST /api/users
DELETE /api/users/:id

# Get user permissions
GET /api/permissions/:user
```

## Usage Examples

### 1. Check Health

```bash
curl http://localhost:8080/health
```

### 2. View Documents (as user)

```bash
curl -X GET http://localhost:8080/api/documents \
  -H "X-User: bob" \
  -H "X-Role: user"
```

### 3. Create Document (as manager)

```bash
curl -X POST http://localhost:8080/api/documents \
  -H "X-User: alice" \
  -H "X-Role: manager" \
  -H "Content-Type: application/json" \
  -d '{"title": "New Document", "content": "Hello World"}'
```

### 4. Delete Document (requires admin)

```bash
curl -X DELETE http://localhost:8080/api/documents/1 \
  -H "X-User: admin" \
  -H "X-Role: admin"
```

### 5. Check User Permissions

```bash
curl http://localhost:8080/api/permissions/alice
```

## Casbin Model Explained

### model.conf

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

**Explanation:**
- `request_definition`: Format for authorization requests (subject, object, action)
- `policy_definition`: Format for policy rules
- `role_definition`: Role inheritance structure
- `policy_effect`: Allow if any rule matches
- `matchers`: How to match requests against policies

### policy.csv

```csv
# Permissions
p, admin, /api/*, *
p, manager, /api/documents, GET
p, manager, /api/documents, POST
p, manager, /api/documents, PUT
p, user, /api/documents, GET

# Role inheritance
g, alice, manager
g, bob, user
g, admin_user, admin
```

## Dynamic Policy Management

### Add Permission at Runtime

```go
enforcer.AddPolicy("user", "/api/reports", "GET")
```

### Remove Permission

```go
enforcer.RemovePolicy("user", "/api/reports", "GET")
```

### Add Role Assignment

```go
enforcer.AddGroupingPolicy("charlie", "manager")
```

### Remove Role Assignment

```go
enforcer.RemoveGroupingPolicy("charlie", "manager")
```

## Testing

### Run Tests

```bash
make test
```

### Manual Testing with cURL

```bash
# Test as different users
make test-user    # Bob (user role)
make test-manager # Alice (manager role)
make test-admin   # Admin (admin role)
```

## Customization

### Add New Role

1. Add role to policy.csv:
```csv
g, newuser, newrole
```

2. Add permissions for the role:
```csv
p, newrole, /api/resource, GET
```

### Add New Permission

```csv
p, manager, /api/reports, GET
```

### Add Custom Matching Logic

Modify the matcher in model.conf:
```ini
m = g(r.sub, p.sub) && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)
```

## Admin Interface

Access the web interface at `http://localhost:8080/`

Features:
- View all policies
- Add/remove permissions
- Manage role assignments
- Test authorization decisions

## API Response Format

### Success

```json
{
  "success": true,
  "data": {
    "id": 1,
    "title": "Document"
  }
}
```

### Authorization Failure

```json
{
  "success": false,
  "error": "Forbidden: Insufficient permissions"
}
```

## Common Commands

```bash
# Start server
make run

# Build Docker image
make build

# Run tests
make test

# View policies
make show-policies

# Add user
make add-user USER=charlie ROLE=manager

# Check permission
make check-permission USER=alice OBJ=/api/documents ACT=POST
```

## Troubleshooting

**403 Forbidden errors?**
- Check if user has role: `make show-policies`
- Verify role has permission for the endpoint
- Ensure headers are set correctly (`X-User` and `X-Role`)

**Policies not persisting?**
- Enable auto-save in code
- Use database adapter instead of file adapter
- Check file permissions on policy.csv

**Role inheritance not working?**
- Verify matcher includes `g(r.sub, p.sub)`
- Check role_definition in model.conf
- Ensure grouping policies (g, ...) are in policy.csv

## Advanced Features

### Using Database Adapter

```go
// PostgreSQL
import "github.com/casbin/casbin/v2/persist/postgres-adapter"
adapter := postgresadapter.NewAdapter("postgresql://...")

// MySQL
import "github.com/casbin/casbin/v2/persist/mysql-adapter"
adapter := mysqladapter.NewAdapter("mysql://...")
```

### Adding ABAC (Attribute-Based)

Modify matcher to include attributes:
```ini
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act && r.sub.Department == r.obj.Department
```

### Watching for Policy Changes

```go
import "github.com/casbin/casbin/v2/persist/watcher"

w := rediswatcher.NewWatcher("localhost:6379")
enforcer.SetWatcher(w)
```

## Next Steps

- Add authentication (JWT)
- Implement database adapter
- Add more complex policies
- Create admin dashboard
- Add audit logging

## Resources

- [Casbin Documentation](https://casbin.org/docs/overview)
- [Online Editor](https://casbin.org/editor)
- [Model Examples](https://casbin.org/docs/supported-models)

## License

MIT
