# Multi-Tenant Authorization Example

A complete multi-tenant SaaS application demonstrating tenant isolation and authorization with OPA.

## Overview

This example demonstrates:
- Tenant isolation (data segregation)
- Cross-tenant access prevention
- Hierarchical tenants (parent/child organizations)
- Tenant-specific role permissions
- Shared resources with tenant-scoped access
- OPA policies for multi-tenancy

## Architecture

```
┌─────────────────┐
│  Flask API      │
│  (port 5000)    │
│  - Multi-tenant │
│  - JWT Auth     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   OPA Server    │
│  (port 8181)    │
│  - Tenant       │
│    policies     │
└─────────────────┘
```

## Key Concepts

### Tenant Isolation

Each tenant's data is completely isolated:
- Users can only access their tenant's resources
- No cross-tenant data leakage
- Tenant context in every request

### Hierarchical Tenants

Support for parent-child tenant relationships:
- Parent tenant admins can access child tenant data
- Child tenants are isolated from each other
- Configurable delegation rules

### Tenant-Scoped Roles

Roles are scoped to tenants:
- Same user can have different roles in different tenants
- Tenant admins manage their own users
- Global admins manage all tenants

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.8+ (for local development)

### Run with Docker

```bash
# Start all services
docker-compose up --build

# API: http://localhost:5000
# OPA: http://localhost:8181
```

### Run Locally

```bash
# Terminal 1: Start OPA
docker run -p 8181:8181 openpolicyagent/opa:latest run --server

# Terminal 2: Load policy
curl -X PUT http://localhost:8181/v1/policies/multitenant \
  --data-binary @policy.rego

# Terminal 3: Start Flask app
pip install -r requirements.txt
python app.py
```

## Test Tenants and Users

| Tenant  | User    | Role        | Access                           |
|---------|---------|-------------|----------------------------------|
| acme    | alice   | admin       | Full access to Acme Corp         |
| acme    | bob     | user        | Read Acme Corp resources         |
| globex  | charlie | admin       | Full access to Globex Inc        |
| globex  | diana   | user        | Read Globex Inc resources        |
| system  | root    | superadmin  | Access all tenants               |

## API Endpoints

### Authentication

```bash
# Login
POST /api/auth/login
{
  "username": "alice",
  "password": "alice123",
  "tenant": "acme"
}
```

### Resources (Tenant-Scoped)

```bash
# List resources (own tenant only)
GET /api/resources
Headers: Authorization: Bearer <token>

# Create resource
POST /api/resources
Headers: Authorization: Bearer <token>
{
  "name": "My Resource",
  "type": "document"
}

# Update resource
PUT /api/resources/:id
Headers: Authorization: Bearer <token>

# Delete resource (admin only)
DELETE /api/resources/:id
Headers: Authorization: Bearer <token>
```

### Tenants (Admin Only)

```bash
# List all tenants
GET /api/tenants
Headers: Authorization: Bearer <token>

# Get tenant details
GET /api/tenants/:id
Headers: Authorization: Bearer <token>
```

## Usage Examples

### Example 1: Alice accesses Acme resources

```bash
# Login as Alice (Acme admin)
TOKEN=$(curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"alice123","tenant":"acme"}' \
  | jq -r '.token')

# List Acme resources (succeeds)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5000/api/resources
```

### Example 2: Cross-tenant access prevented

```bash
# Alice (Acme) tries to access Globex resource (fails)
curl -X GET -H "Authorization: Bearer $TOKEN" \
  http://localhost:5000/api/resources/globex-resource-id
# Returns: 403 Forbidden
```

### Example 3: Superadmin access

```bash
# Login as root (superadmin)
TOKEN=$(curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"root","password":"root123","tenant":"system"}' \
  | jq -r '.token')

# Access any tenant's resources (succeeds)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5000/api/tenants
```

## OPA Policy Explained

### Tenant Isolation Rule

```rego
# Users can only access resources in their tenant
allow {
    input.user.tenant == input.resource.tenant
    user_has_permission(input.user, input.action)
}
```

### Hierarchical Access

```rego
# Parent tenant admins can access child tenant data
allow {
    input.user.role == "admin"
    is_parent_tenant(input.user.tenant, input.resource.tenant)
}
```

### Superadmin Override

```rego
# Superadmins can access everything
allow {
    input.user.role == "superadmin"
}
```

## Multi-Tenancy Patterns

### 1. Separate Databases

Most isolated, best for compliance:
```python
# Each tenant gets its own database
db = get_tenant_database(tenant_id)
```

### 2. Shared Database, Separate Schemas

Good balance of isolation and cost:
```python
# PostgreSQL schemas per tenant
db.execute(f"SET search_path TO tenant_{tenant_id}")
```

### 3. Shared Tables with Tenant Column

Most cost-effective, used in this example:
```python
# Filter all queries by tenant_id
query.filter_by(tenant_id=current_tenant.id)
```

## Security Considerations

### Always Validate Tenant Context

```python
# BAD: Trust client-provided tenant
tenant_id = request.json.get('tenant_id')

# GOOD: Use authenticated user's tenant
tenant_id = current_user.tenant_id
```

### Prevent Tenant Enumeration

```python
# Return 404 instead of 403 for cross-tenant access
if resource.tenant_id != current_user.tenant_id:
    return not_found()  # Not forbidden()
```

### Audit Cross-Tenant Access

```python
# Log all cross-tenant access attempts
if user.tenant != resource.tenant:
    audit_log.warning(f"Cross-tenant access attempt: {user} -> {resource}")
```

## Testing

### Run Tests

```bash
make test
```

### Manual Testing

```bash
# Test tenant isolation
make test-isolation

# Test hierarchical access
make test-hierarchy

# Test admin permissions
make test-admin
```

## Configuration

### Environment Variables

```bash
# Flask app
export FLASK_ENV=development
export SECRET_KEY=your-secret-key
export OPA_URL=http://localhost:8181

# OPA
export OPA_LOG_LEVEL=debug
```

### Tenant Configuration

Edit `tenants.json` to add/modify tenants:

```json
{
  "tenants": [
    {
      "id": "acme",
      "name": "Acme Corporation",
      "parent": null,
      "active": true
    },
    {
      "id": "acme-subsidiary",
      "name": "Acme Subsidiary",
      "parent": "acme",
      "active": true
    }
  ]
}
```

## Common Patterns

### Tenant Context Middleware

```python
@app.before_request
def set_tenant_context():
    if current_user:
        g.tenant_id = current_user.tenant_id
```

### Scoped Queries

```python
def get_resources():
    # Automatically filter by current tenant
    return Resource.query.filter_by(
        tenant_id=g.tenant_id
    ).all()
```

### Tenant-Specific Settings

```python
def get_tenant_settings():
    return Settings.query.filter_by(
        tenant_id=g.tenant_id
    ).first_or_404()
```

## Troubleshooting

**Cross-tenant access succeeding?**
- Check OPA policy is loaded
- Verify tenant_id is in JWT token
- Ensure middleware sets tenant context

**Performance issues with many tenants?**
- Add database indexes on tenant_id
- Use connection pooling
- Consider caching OPA decisions

**Tenant data visible to wrong users?**
- Audit all database queries
- Ensure global queries are intentional
- Add automated tests for tenant isolation

## Production Considerations

1. **Database Indexes**: Index all `tenant_id` columns
2. **Connection Pooling**: One pool per tenant or shared pool
3. **Caching**: Tenant-scoped cache keys
4. **Monitoring**: Track cross-tenant access attempts
5. **Backups**: Per-tenant backup schedules
6. **Migrations**: Test with multiple tenants

## Next Steps

- Implement tenant onboarding workflow
- Add tenant-specific branding
- Implement usage-based billing per tenant
- Add tenant analytics dashboard
- Implement tenant data export/import

## Resources

- [Multi-Tenancy Patterns](https://docs.microsoft.com/en-us/azure/architecture/guide/multitenant/overview)
- [OPA Multi-Tenancy](https://www.openpolicyagent.org/docs/latest/#multi-tenancy)
- [SaaS Tenant Isolation](https://aws.amazon.com/blogs/apn/saas-tenant-isolation-strategies/)

## License

MIT
