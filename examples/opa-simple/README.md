# OPA Simple Example

A simple demonstration of Open Policy Agent (OPA) for authorization decisions.

## Overview

This example demonstrates:
- Basic RBAC policies in Rego
- Running OPA server
- Making authorization queries
- Testing policies

## Architecture

```
┌─────────────┐
│   Client    │
│ (app.py)    │
└──────┬──────┘
       │ HTTP
       ▼
┌─────────────┐
│ OPA Server  │
│  (port 8181)│
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Policy    │
│ (policy.rego)│
└─────────────┘
```

## Files

- `policy.rego` - Authorization policy in Rego
- `data.json` - User roles and permissions data
- `app.py` - Python client for querying OPA
- `docker-compose.yml` - Docker setup for OPA server
- `test_policy.rego` - Unit tests for the policy
- `Makefile` - Common commands

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.8+ (for client)

### Run the Example

1. **Start OPA server**:
```bash
docker-compose up -d
```

2. **Load the policy**:
```bash
make load-policy
```

3. **Load the data**:
```bash
make load-data
```

4. **Test authorization**:
```bash
python app.py
```

## Policy Overview

The policy implements:
- **RBAC** - Role-based access control
- **Ownership** - Resource owner permissions
- **Admin override** - Admins can do anything

### Roles

- `admin` - Full access to all resources
- `editor` - Can read and write their own resources
- `viewer` - Can only read resources

### Example Queries

**Can Alice (admin) delete any resource?**
```bash
curl -X POST http://localhost:8181/v1/data/authz/allow \
  -d '{
    "input": {
      "user": "alice",
      "action": "delete",
      "resource": "document123"
    }
  }'
```

**Can Bob (editor) write his own resource?**
```bash
curl -X POST http://localhost:8181/v1/data/authz/allow \
  -d '{
    "input": {
      "user": "bob",
      "action": "write",
      "resource": "document456"
    }
  }'
```

## Testing the Policy

Run OPA tests:
```bash
make test
```

Or manually:
```bash
docker run --rm -v $(pwd):/policies openpolicyagent/opa:latest \
  test /policies -v
```

## Understanding the Policy

### policy.rego

```rego
package authz

# Default deny
default allow = false

# Admins can do anything
allow {
    user_has_role(input.user, "admin")
}

# Editors can read and write their own resources
allow {
    user_has_role(input.user, "editor")
    input.action in ["read", "write"]
    resource_owner(input.resource, input.user)
}

# Viewers can read any resource
allow {
    user_has_role(input.user, "viewer")
    input.action == "read"
}

# Helper functions
user_has_role(user, role) {
    data.users[user].roles[_] == role
}

resource_owner(resource, user) {
    data.resources[resource].owner == user
}
```

## Customization

### Add New Roles

Edit `data.json`:
```json
{
  "users": {
    "newuser": {
      "roles": ["custom_role"]
    }
  }
}
```

Add policy rule in `policy.rego`:
```rego
allow {
    user_has_role(input.user, "custom_role")
    input.action == "custom_action"
}
```

### Add New Actions

Simply reference them in your policy rules:
```rego
allow {
    user_has_role(input.user, "moderator")
    input.action == "approve"
}
```

## Common Commands

```bash
# Start OPA
make up

# Stop OPA
make down

# Load policy
make load-policy

# Load data
make load-data

# Run tests
make test

# Check policy syntax
make check

# Watch logs
docker-compose logs -f
```

## API Examples

### Python
```python
import requests

response = requests.post(
    "http://localhost:8181/v1/data/authz/allow",
    json={
        "input": {
            "user": "alice",
            "action": "read",
            "resource": "document123"
        }
    }
)
print(response.json()["result"])  # True or False
```

### JavaScript
```javascript
const response = await fetch('http://localhost:8181/v1/data/authz/allow', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    input: {
      user: 'alice',
      action: 'read',
      resource: 'document123'
    }
  })
});
const data = await response.json();
console.log(data.result); // true or false
```

### cURL
```bash
curl -X POST http://localhost:8181/v1/data/authz/allow \
  -H 'Content-Type: application/json' \
  -d '{"input": {"user": "alice", "action": "read", "resource": "doc1"}}'
```

## Troubleshooting

**OPA not responding?**
- Check if container is running: `docker-compose ps`
- View logs: `docker-compose logs opa`

**Policy not loaded?**
- Reload: `make load-policy`
- Check syntax: `make check`

**Authorization always false?**
- Verify data is loaded: `curl http://localhost:8181/v1/data`
- Check input format matches policy expectations

## Next Steps

- Explore the [OPA documentation](https://www.openpolicyagent.org/docs/latest/)
- Try modifying the policy rules
- Add more complex scenarios
- Integrate with your application
- Check out the OPA playground: https://play.openpolicyagent.org/

## License

MIT
