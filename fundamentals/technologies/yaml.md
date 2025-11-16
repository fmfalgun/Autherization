# YAML Fundamentals for Authorization

## Overview

**YAML (YAML Ain't Markup Language)** is a human-readable data serialization format commonly used for configuration files, including authorization policies, role definitions, and permission schemas.

## Why YAML in Authorization?

- **Human-Readable**: Easy to write and review
- **Widely Supported**: Most authorization tools support YAML
- **Version Control Friendly**: Plain text, works well with git
- **Hierarchical**: Natural representation of nested structures
- **Comments**: Inline documentation

## Basic Syntax

### Key-Value Pairs

```yaml
# Simple key-value
name: alice
role: admin
active: true
age: 30
```

### Lists/Arrays

```yaml
# Inline list
permissions: [read, write, delete]

# Block list
permissions:
  - read
  - write
  - delete

# List of objects
users:
  - name: alice
    role: admin
  - name: bob
    role: viewer
```

### Objects/Dictionaries

```yaml
# Nested object
user:
  name: alice
  email: alice@example.com
  role: admin
  permissions:
    - read
    - write
    - delete
```

### Multi-Line Strings

```yaml
# Literal block (preserves newlines)
description: |
  This is a multi-line
  description that preserves
  line breaks.

# Folded block (joins lines)
summary: >
  This is a long
  sentence that will
  be joined into one line.
```

## Authorization Schemas in YAML

### Example 1: RBAC Configuration

```yaml
# Role definitions
roles:
  admin:
    description: Full system access
    permissions:
      - read:*
      - write:*
      - delete:*
      - admin:users
      - admin:roles

  editor:
    description: Content management
    permissions:
      - read:content
      - write:content
      - delete:own_content
      - read:users

  viewer:
    description: Read-only access
    permissions:
      - read:content
      - read:users

# User role assignments
user_roles:
  alice@example.com:
    - admin
  bob@example.com:
    - editor
  carol@example.com:
    - viewer
```

### Example 2: Resource Permissions

```yaml
resources:
  document:
    actions:
      - read
      - write
      - delete
      - share
    policies:
      - name: owner_full_access
        effect: allow
        principals:
          - type: user
            condition: resource.owner == user.id
        actions: ["*"]

      - name: shared_read_access
        effect: allow
        principals:
          - type: user
            condition: user.id in resource.shared_with
        actions: ["read"]

  database:
    actions:
      - query
      - insert
      - update
      - delete
    policies:
      - name: engineer_read_write
        effect: allow
        principals:
          - type: role
            value: engineer
        actions: ["query", "insert", "update"]
        conditions:
          - environment.network == "corporate"
```

### Example 3: Policy Document

```yaml
# Authorization policy
policy:
  name: engineering_document_access
  version: "1.0"
  description: Engineers can access engineering documents during business hours

  subjects:
    - type: user
      attributes:
        department: engineering

  resources:
    - type: document
      attributes:
        category: technical

  actions:
    - read
    - write

  conditions:
    - name: business_hours
      expression: |
        hour >= 9 AND hour <= 17
    - name: corporate_network
      expression: |
        ip_address.startsWith("10.0.")

  effect: allow
```

### Example 4: Kubernetes RBAC

```yaml
# Role definition
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: production
  name: pod-reader
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "watch", "list"]

---
# RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: production
subjects:
  - kind: User
    name: alice
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

### Example 5: Casbin Policy

```yaml
# Casbin model
model: |
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

# Casbin policy
policy:
  p:
    - [alice, data1, read]
    - [alice, data1, write]
    - [bob, data2, read]
    - [data_group_admin, data_group, write]

  g:
    - [alice, admin]
    - [admin, data_group_admin]
```

### Example 6: AWS IAM-like Policy

```yaml
# Policy document
Version: "2012-10-17"
Statement:
  - Sid: AllowReadDocuments
    Effect: Allow
    Principal:
      AWS:
        - "arn:aws:iam::123456789012:user/alice"
        - "arn:aws:iam::123456789012:role/engineers"
    Action:
      - "s3:GetObject"
      - "s3:ListBucket"
    Resource:
      - "arn:aws:s3:::my-bucket/*"
      - "arn:aws:s3:::my-bucket"
    Condition:
      IpAddress:
        "aws:SourceIp": "203.0.113.0/24"
      StringEquals:
        "s3:x-amz-server-side-encryption": "AES256"

  - Sid: AllowWriteOwnFolder
    Effect: Allow
    Principal:
      AWS: "*"
    Action:
      - "s3:PutObject"
    Resource:
      - "arn:aws:s3:::my-bucket/${aws:username}/*"
```

## YAML Features

### Anchors and Aliases (DRY)

```yaml
# Define an anchor
default_permissions: &default_perms
  - read
  - write

# Reuse with alias
admin:
  permissions:
    - *default_perms
    - delete
    - admin

editor:
  permissions: *default_perms

# Merge keys
base_config: &base
  timeout: 30
  retries: 3

production:
  <<: *base
  timeout: 60  # Override
  env: production
```

### Data Types

```yaml
# String
name: "alice"
role: 'admin'
unquoted: works too

# Number
age: 30
price: 99.99
scientific: 1.2e+3

# Boolean
active: true
disabled: false
yes_value: yes  # true
no_value: no    # false

# Null
nothing: null
tilde: ~  # also null

# Date
created: 2025-11-16
timestamp: 2025-11-16T10:30:00Z

# Arrays
inline: [1, 2, 3]
block:
  - item1
  - item2

# Objects
inline: {name: alice, role: admin}
block:
  name: alice
  role: admin
```

## Best Practices for Authorization YAML

### 1. Clear Structure

```yaml
# GOOD: Well-organized
authorization:
  roles:
    admin:
      permissions: [...]
  policies:
    document_access:
      rules: [...]

# BAD: Flat and confusing
admin_permissions: [...]
document_access_rules: [...]
```

### 2. Use Comments

```yaml
roles:
  # Full system administrator with all permissions
  # Should only be assigned to trusted personnel
  admin:
    permissions:
      - read:*
      - write:*
      - delete:*  # Including user deletion
```

### 3. Descriptive Names

```yaml
# GOOD
engineering_team_document_read_access:
  ...

# BAD
policy_1:
  ...
```

### 4. Versioning

```yaml
apiVersion: v1
kind: AuthorizationPolicy
metadata:
  version: "2.1.0"
  lastModified: "2025-11-16"
  author: "security-team@example.com"
spec:
  ...
```

### 5. Validation Schema

```yaml
# JSON Schema for validation
$schema: "http://json-schema.org/draft-07/schema#"
type: object
required:
  - roles
  - policies
properties:
  roles:
    type: object
    additionalProperties:
      type: object
      required:
        - permissions
      properties:
        permissions:
          type: array
          items:
            type: string
```

## Common Patterns

### Multi-Tenant Configuration

```yaml
tenants:
  acme-corp:
    users:
      alice:
        roles: [admin]
      bob:
        roles: [editor]
    resources:
      documents: 150
      storage_gb: 100

  widgets-inc:
    users:
      carol:
        roles: [admin]
    resources:
      documents: 50
      storage_gb: 25
```

### Environment-Specific Policies

```yaml
# Base configuration
base: &base
  timeout: 30
  max_retries: 3
  encryption: true

# Development
development:
  <<: *base
  logging: debug
  strict_mode: false

# Production
production:
  <<: *base
  logging: error
  strict_mode: true
  mfa_required: true
```

### Conditional Access

```yaml
policies:
  - name: business_hours_access
    conditions:
      time:
        after: "09:00"
        before: "17:00"
      days:
        - monday
        - tuesday
        - wednesday
        - thursday
        - friday

  - name: trusted_network
    conditions:
      ip_ranges:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
```

## Integration with Authorization Tools

### OPA Bundle

```yaml
# .manifest file
revision: "abc123"
roots:
  - authz
  - data

# Data file
data.yaml:
  users:
    alice:
      role: admin
      department: engineering
```

### Keycloak Client

```yaml
clientId: my-app
rootUrl: https://app.example.com
redirectUris:
  - "https://app.example.com/*"
webOrigins:
  - "https://app.example.com"
authorizationSettings:
  policyEnforcementMode: ENFORCING
  resources:
    - name: "Admin Resource"
      type: "urn:my-app:resources:admin"
      uris:
        - "/admin/*"
  policies:
    - name: "Admin Only"
      type: "role"
      logic: POSITIVE
      config:
        roles:
          - name: "admin"
```

## Validation Tools

### yamllint

```bash
# Install
pip install yamllint

# Validate
yamllint policy.yaml

# Custom config
cat > .yamllint <<EOF
extends: default
rules:
  line-length:
    max: 120
  indentation:
    spaces: 2
EOF
```

### Online Validators

- [YAML Lint](http://www.yamllint.com/)
- [Code Beautify YAML Validator](https://codebeautify.org/yaml-validator)

## Common Mistakes

### 1. Indentation Issues

```yaml
# WRONG: Inconsistent indentation
user:
  name: alice
   role: admin  # Extra space

# CORRECT
user:
  name: alice
  role: admin
```

### 2. Unquoted Special Characters

```yaml
# WRONG: Unquoted colon
description: Error: Access denied

# CORRECT
description: "Error: Access denied"
```

### 3. Incorrect List Syntax

```yaml
# WRONG: Mixed syntax
permissions:
  - read
  write  # Missing dash

# CORRECT
permissions:
  - read
  - write
```

## Converting Between Formats

### YAML to JSON

```bash
# Using Python
python -c 'import sys, yaml, json; json.dump(yaml.safe_load(sys.stdin), sys.stdout, indent=2)' < policy.yaml > policy.json

# Using yq
yq eval -o=json policy.yaml > policy.json
```

### JSON to YAML

```bash
# Using Python
python -c 'import sys, yaml, json; yaml.dump(json.load(sys.stdin), sys.stdout)' < policy.json > policy.yaml

# Using yq
yq eval -P policy.json > policy.yaml
```

## Tools and Libraries

### Go
```go
import "gopkg.in/yaml.v3"

type Policy struct {
    Name    string   `yaml:"name"`
    Roles   []string `yaml:"roles"`
    Actions []string `yaml:"actions"`
}

data, _ := ioutil.ReadFile("policy.yaml")
var policy Policy
yaml.Unmarshal(data, &policy)
```

### Python
```python
import yaml

with open('policy.yaml', 'r') as f:
    policy = yaml.safe_load(f)

print(policy['roles'])
```

### JavaScript
```javascript
const yaml = require('js-yaml');
const fs = require('fs');

const policy = yaml.load(fs.readFileSync('policy.yaml', 'utf8'));
console.log(policy.roles);
```

## Further Reading

- [YAML Specification](https://yaml.org/spec/)
- [YAML Multiline Strings](https://yaml-multiline.info/)
- [yamllint Documentation](https://yamllint.readthedocs.io/)

## Next Steps

- Learn [Docker](./docker.md) for containerizing authorization services
- Explore [Go](./go.md) for building authorization services
- Review [Policy Making](../policy-standards/policy-making.md)
- See [OPA](../../frameworks/opa/) for Rego vs YAML policies
