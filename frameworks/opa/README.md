# OPA (Open Policy Agent)

## Overview

**Open Policy Agent (OPA)** is an open-source, general-purpose policy engine that unifies policy enforcement across the stack. OPA provides a declarative policy language (Rego) to express fine-grained authorization rules.

**Website**: [openpolicyagent.org](https://www.openpolicyagent.org/)
**GitHub**: [github.com/open-policy-agent/opa](https://github.com/open-policy-agent/opa)
**License**: Apache 2.0

## Why OPA?

- **Decoupled Architecture**: Separate policy from code
- **Cloud-Native**: Kubernetes, microservices, service mesh
- **Declarative**: Write policies in Rego, not imperative code
- **Flexible**: Works with any data source and service
- **High Performance**: Sub-millisecond policy evaluation
- **Well-Tested**: Comprehensive testing framework
- **Active Community**: CNCF graduated project

## Use Cases

- **Kubernetes Admission Control**: Validate/mutate resources
- **API Authorization**: Protect REST/GraphQL APIs
- **Service Mesh**: Envoy, Istio authorization
- **CI/CD Pipelines**: Terraform, Docker, CI validation
- **Data Filtering**: SQL, NoSQL query authorization
- **SSH/sudo Authorization**: Linux system access control

## Quick Start

### Installation

```bash
# macOS
brew install opa

# Linux
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod +x opa
sudo mv opa /usr/local/bin/

# Docker
docker pull openpolicyagent/opa:latest

# Verify
opa version
```

### Your First Policy

Create `policy.rego`:

```rego
package example

# Allow admins to do anything
allow {
    input.user.role == "admin"
}

# Allow users to view their own resources
allow {
    input.user.id == input.resource.owner
    input.action == "view"
}

# Deny by default (implicit)
default allow = false
```

### Evaluate Policy

```bash
# Create input file
cat > input.json <<EOF
{
  "user": {
    "id": "alice",
    "role": "user"
  },
  "resource": {
    "id": "doc-123",
    "owner": "alice"
  },
  "action": "view"
}
EOF

# Evaluate
opa eval -i input.json -d policy.rego "data.example.allow"

# Output:
# {
#   "result": [
#     {
#       "expressions": [
#         {
#           "value": true,
#           "text": "data.example.allow",
#           "location": {...}
#         }
#       ]
#     }
#   ]
# }
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Your Service                       │
│                                                     │
│  ┌────────────┐        ┌──────────────┐           │
│  │   Code     │───────>│ OPA Library  │           │
│  │            │<───────│  (Embedded)  │           │
│  └────────────┘        └──────────────┘           │
│                              │                      │
└──────────────────────────────┼──────────────────────┘
                               │
                  ┌────────────▼──────────────┐
                  │   Policies (Rego files)   │
                  └───────────────────────────┘
                               │
                  ┌────────────▼──────────────┐
                  │   Data (JSON/YAML)        │
                  └───────────────────────────┘
```

### Alternative: OPA as Sidecar

```
┌──────────────┐         ┌──────────────┐
│              │  HTTP   │              │
│ Your Service │────────>│  OPA Server  │
│              │<────────│   (Sidecar)  │
└──────────────┘         └──────────────┘
                                │
                     ┌──────────▼─────────┐
                     │ Policies + Data     │
                     └────────────────────┘
```

## Running OPA Server

### Start Server

```bash
# Basic server
opa run --server

# With policies
opa run --server policy.rego

# With bundle server
opa run --server --config-file config.yaml

# Production mode
opa run --server \
  --addr=0.0.0.0:8181 \
  --log-level=info \
  --log-format=json \
  policy.rego
```

### Query via REST API

```bash
# Load policy
curl -X PUT http://localhost:8181/v1/policies/authz \
  --data-binary @policy.rego

# Query decision
curl -X POST http://localhost:8181/v1/data/example/allow \
  -H 'Content-Type: application/json' \
  -d '{
    "input": {
      "user": {"id": "alice", "role": "user"},
      "resource": {"owner": "alice"},
      "action": "view"
    }
  }'

# Response:
# {"result": true}
```

### Load Data

```bash
# Upload data
curl -X PUT http://localhost:8181/v1/data/users \
  -H 'Content-Type: application/json' \
  -d '{
    "alice": {"role": "admin", "department": "engineering"},
    "bob": {"role": "user", "department": "sales"}
  }'

# Query data
curl http://localhost:8181/v1/data/users/alice

# Response:
# {"result": {"role": "admin", "department": "engineering"}}
```

## Integration Examples

### Go Application

```go
package main

import (
    "context"
    "fmt"

    "github.com/open-policy-agent/opa/rego"
)

func main() {
    // Load policy
    module := `
package authz

allow {
    input.user.role == "admin"
}

allow {
    input.user.id == input.resource.owner
}
`

    // Prepare query
    query, err := rego.New(
        rego.Query("data.authz.allow"),
        rego.Module("authz.rego", module),
    ).PrepareForEval(context.Background())

    if err != nil {
        panic(err)
    }

    // Input
    input := map[string]interface{}{
        "user": map[string]interface{}{
            "id":   "alice",
            "role": "user",
        },
        "resource": map[string]interface{}{
            "owner": "alice",
        },
    }

    // Evaluate
    results, err := query.Eval(context.Background(), rego.EvalInput(input))
    if err != nil {
        panic(err)
    }

    // Check result
    if len(results) > 0 && results[0].Expressions[0].Value == true {
        fmt.Println("Access allowed")
    } else {
        fmt.Println("Access denied")
    }
}
```

### HTTP Middleware

```go
package main

import (
    "bytes"
    "encoding/json"
    "net/http"
)

type OPAClient struct {
    url string
}

func (c *OPAClient) Authorize(user, action, resource string) (bool, error) {
    input := map[string]interface{}{
        "user":     user,
        "action":   action,
        "resource": resource,
    }

    body := map[string]interface{}{"input": input}
    jsonData, _ := json.Marshal(body)

    resp, err := http.Post(
        c.url+"/v1/data/authz/allow",
        "application/json",
        bytes.NewBuffer(jsonData),
    )
    if err != nil {
        return false, err
    }
    defer resp.Body.Close()

    var result struct {
        Result bool `json:"result"`
    }
    json.NewDecoder(resp.Body).Decode(&result)
    return result.Result, nil
}

func AuthzMiddleware(opa *OPAClient) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            user := r.Header.Get("X-User-ID")
            resource := r.URL.Path
            action := r.Method

            allowed, err := opa.Authorize(user, action, resource)
            if err != nil || !allowed {
                http.Error(w, "Forbidden", http.StatusForbidden)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}
```

### Kubernetes Admission Controller

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: opa-policy
  namespace: opa
data:
  policy.rego: |
    package kubernetes.admission

    deny[msg] {
      input.request.kind.kind == "Pod"
      image := input.request.object.spec.containers[_].image
      not startswith(image, "myregistry.com/")
      msg := sprintf("Image %v is not from approved registry", [image])
    }
```

### Envoy/Istio Integration

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: opa-authz
spec:
  action: CUSTOM
  provider:
    name: opa
  rules:
  - to:
    - operation:
        paths: ["/api/*"]
```

## Bundle Management

### Bundle Structure

```
bundle/
├── .manifest
├── data.json
└── policies/
    ├── authz.rego
    └── rbac.rego
```

### Build Bundle

```bash
# Create bundle directory
mkdir bundle
mkdir bundle/policies

# Add policies
cp policy.rego bundle/policies/

# Add data
cat > bundle/data.json <<EOF
{
  "roles": {
    "admin": ["read", "write", "delete"],
    "user": ["read", "write"]
  }
}
EOF

# Build bundle
opa build -b bundle/ -o bundle.tar.gz

# Inspect bundle
tar -tzf bundle.tar.gz
```

### Bundle Server

```yaml
# config.yaml
bundles:
  authz:
    service: bundle-service
    resource: bundles/authz.tar.gz
    polling:
      min_delay_seconds: 10
      max_delay_seconds: 30

services:
  bundle-service:
    url: https://bundle-server.example.com
    credentials:
      bearer:
        token: "secret-token"
```

```bash
# Run with bundle config
opa run --server --config-file config.yaml
```

## Testing Policies

### Unit Tests

Create `policy_test.rego`:

```rego
package example_test

import data.example

# Test admin access
test_admin_allowed {
    example.allow with input as {
        "user": {"role": "admin"},
        "action": "delete"
    }
}

# Test user can view own resource
test_owner_view_allowed {
    example.allow with input as {
        "user": {"id": "alice"},
        "resource": {"owner": "alice"},
        "action": "view"
    }
}

# Test user cannot delete others' resources
test_non_owner_delete_denied {
    not example.allow with input as {
        "user": {"id": "alice"},
        "resource": {"owner": "bob"},
        "action": "delete"
    }
}
```

### Run Tests

```bash
# Run all tests
opa test policy.rego policy_test.rego

# Verbose output
opa test -v policy.rego policy_test.rego

# Coverage
opa test --coverage policy.rego policy_test.rego

# Output:
# data.example_test.test_admin_allowed: PASS (1.2ms)
# data.example_test.test_owner_view_allowed: PASS (0.8ms)
# data.example_test.test_non_owner_delete_denied: PASS (0.9ms)
# ────────────────────────────────────────────────────
# PASS: 3/3
```

## Docker Deployment

### Dockerfile

```dockerfile
FROM openpolicyagent/opa:latest

# Copy policies
COPY policies /policies

# Copy data
COPY data.json /data.json

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8181/health || exit 1

# Run OPA
ENTRYPOINT ["/opa"]
CMD ["run", "--server", "--addr=:8181", "/policies"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  opa:
    image: openpolicyagent/opa:latest
    ports:
      - "8181:8181"
    volumes:
      - ./policies:/policies:ro
      - ./data.json:/data.json:ro
    command:
      - "run"
      - "--server"
      - "--addr=:8181"
      - "/policies"
    healthcheck:
      test: ["CMD", "wget", "--spider", "http://localhost:8181/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

## Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: opa
  labels:
    app: opa
spec:
  replicas: 3
  selector:
    matchLabels:
      app: opa
  template:
    metadata:
      labels:
        app: opa
    spec:
      containers:
      - name: opa
        image: openpolicyagent/opa:latest
        args:
          - "run"
          - "--server"
          - "--addr=:8181"
          - "/policies"
        ports:
        - containerPort: 8181
        volumeMounts:
        - name: policies
          mountPath: /policies
          readOnly: true
        livenessProbe:
          httpGet:
            path: /health
            port: 8181
        readinessProbe:
          httpGet:
            path: /health?bundles
            port: 8181
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: policies
        configMap:
          name: opa-policies
---
apiVersion: v1
kind: Service
metadata:
  name: opa
spec:
  selector:
    app: opa
  ports:
  - protocol: TCP
    port: 8181
    targetPort: 8181
```

## Performance Tuning

### Caching

```rego
# Cache expensive operations
allow {
    cached_user_roles[input.user.id][_] == "admin"
}

# Computed once, cached
cached_user_roles[user_id] = roles {
    user := data.users[user_id]
    roles := user.roles
}
```

### Indexing

```bash
# Enable partial evaluation for better performance
opa build --optimize=1 policy.rego
```

### Benchmarking

```bash
# Benchmark policy
opa test --bench policy.rego policy_test.rego
```

## Best Practices

1. **Default Deny**: Always start with `default allow = false`
2. **Modular Policies**: Split into smaller, focused modules
3. **Test Coverage**: Aim for >80% policy coverage
4. **Version Control**: Track policies in git
5. **CI/CD Integration**: Test policies in pipelines
6. **Bundle Deployment**: Use bundles for production
7. **Monitoring**: Track policy evaluation metrics
8. **Documentation**: Comment complex rules
9. **Least Privilege**: Grant minimal necessary permissions
10. **Regular Audits**: Review policies periodically

## Monitoring

### Prometheus Metrics

```bash
# OPA exposes metrics at /metrics
curl http://localhost:8181/metrics

# Key metrics:
# - http_request_duration_seconds
# - policy_evaluation_duration_seconds
# - bundle_download_duration_seconds
```

### Logging

```yaml
# config.yaml
decision_logs:
  service: decision-log-service
  reporting:
    min_delay_seconds: 10
    max_delay_seconds: 30

services:
  decision-log-service:
    url: https://logs.example.com
    credentials:
      bearer:
        token: "secret"
```

## Comparison with Other Frameworks

| Feature | OPA | Casbin | SpiceDB |
|---------|-----|--------|---------|
| **Model** | ABAC | RBAC/ABAC | ReBAC |
| **Language** | Rego | Model file | Schema |
| **Performance** | Sub-ms | Sub-ms | Low-ms |
| **Complexity** | Medium | Low | Medium |
| **Use Case** | General-purpose | Access control | Relationships |
| **Cloud-Native** | Excellent | Good | Excellent |

## Further Resources

- **Documentation**: [openpolicyagent.org/docs](https://www.openpolicyagent.org/docs/latest/)
- **Playground**: [play.openpolicyagent.org](https://play.openpolicyagent.org/)
- **Styra Academy**: [academy.styra.com](https://academy.styra.com/)
- **OPA Book**: Comprehensive guide to OPA

## Community

- **Slack**: [slack.openpolicyagent.org](https://slack.openpolicyagent.org/)
- **GitHub Discussions**: [github.com/open-policy-agent/opa/discussions](https://github.com/open-policy-agent/opa/discussions)
- **Stack Overflow**: Tag `open-policy-agent`

## Next Steps

- Review [Rego Language](../../fundamentals/technologies/rego.md)
- Understand [ABAC Concepts](../../fundamentals/concepts/abac.md)
- Explore [Policy Making Techniques](../../fundamentals/policy-standards/policy-making.md)
- Check [Comparative Analysis](../../COMPARISON.md)
