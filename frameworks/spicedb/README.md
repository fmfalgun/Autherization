# SpiceDB

## Overview

**SpiceDB** is an open-source, Google Zanzibar-inspired database system for managing security-critical application permissions. It provides relationship-based access control (ReBAC) with strong consistency guarantees, designed to scale to billions of permission checks.

**Website**: [authzed.com/spicedb](https://authzed.com/spicedb)
**GitHub**: [github.com/authzed/spicedb](https://github.com/authzed/spicedb)
**License**: Apache 2.0
**Company**: AuthZed

## Why SpiceDB?

- **Relationship-Based**: Model complex permission graphs like Google Drive
- **Scalable**: Handles billions of relationships
- **Consistent**: Strong consistency with snapshot reads
- **Zanzibar-Inspired**: Based on Google's proven model
- **gRPC API**: High-performance native protocol
- **Schema Evolution**: Version and migrate schemas
- **Real-Time**: Immediate permission updates
- **Battle-Tested**: Production-ready implementation

## Use Cases

- **Google Drive-Like Sharing**: Files, folders, hierarchies
- **Social Networks**: Friend relationships, privacy
- **Multi-Tenant SaaS**: Organization hierarchies
- **Document Management**: Complex sharing scenarios
- **Cloud IAM**: Resource hierarchies
- **Collaborative Tools**: Teams, projects, workspaces

## Core Concepts

### Relationship Tuples

Permission data stored as **(object, relation, subject)**:

```
document:readme#viewer@user:alice
document:readme#owner@user:bob
folder:documents#parent@document:readme
```

### Schema

Defines object types and their relations:

```zed
definition user {}

definition document {
    relation owner: user
    relation viewer: user
    relation parent: folder

    permission view = viewer + owner
    permission edit = owner
    permission share = owner
}

definition folder {
    relation owner: user
    relation viewer: user

    permission view = viewer + owner
}
```

### Permissions

Computed from relationships using rewrite rules:

```
permission view = viewer + owner + parent->view
```

## Quick Start

### Installation

#### Docker
```bash
docker run -d \
  --name spicedb \
  -p 50051:50051 \
  authzed/spicedb serve \
  --grpc-preshared-key "dev-key" \
  --datastore-engine memory

# For production (with PostgreSQL)
docker run -d \
  --name spicedb \
  -p 50051:50051 \
  authzed/spicedb serve \
  --grpc-preshared-key "your-secret-key" \
  --datastore-engine postgres \
  --datastore-conn-uri "postgres://user:pass@localhost/spicedb"
```

#### Binary
```bash
# Download
curl -L https://github.com/authzed/spicedb/releases/latest/download/spicedb-linux-amd64 -o spicedb
chmod +x spicedb

# Run
./spicedb serve \
  --grpc-preshared-key "dev-key" \
  --datastore-engine memory
```

### Install CLI (zed)

```bash
# macOS
brew install authzed/tap/zed

# Linux
curl -L https://github.com/authzed/zed/releases/latest/download/zed-linux-amd64 -o zed
chmod +x zed
sudo mv zed /usr/local/bin/
```

### Basic Example

#### 1. Define Schema

**schema.zed**:
```zed
definition user {}

definition document {
    relation owner: user
    relation viewer: user

    permission view = viewer + owner
    permission edit = owner
}
```

#### 2. Write Schema

```bash
zed schema write schema.zed \
  --endpoint localhost:50051 \
  --insecure \
  --token "dev-key"
```

#### 3. Create Relationships

```bash
# Alice owns document:readme
zed relationship create \
  document:readme owner user:alice \
  --endpoint localhost:50051 \
  --insecure \
  --token "dev-key"

# Bob can view document:readme
zed relationship create \
  document:readme viewer user:bob \
  --endpoint localhost:50051 \
  --insecure \
  --token "dev-key"
```

#### 4. Check Permissions

```bash
# Can Alice view document:readme?
zed permission check \
  document:readme view user:alice \
  --endpoint localhost:50051 \
  --insecure \
  --token "dev-key"
# Result: true

# Can Bob edit document:readme?
zed permission check \
  document:readme edit user:bob \
  --endpoint localhost:50051 \
  --insecure \
  --token "dev-key"
# Result: false
```

## Schema Language

### Definitions

```zed
definition user {}

definition group {
    relation member: user
}

definition document {
    relation owner: user
    relation editor: user | group#member
    relation viewer: user | group#member
    relation parent: folder

    permission view = viewer + editor + owner + parent->view
    permission edit = editor + owner + parent->edit
    permission delete = owner
}

definition folder {
    relation owner: user
    relation viewer: user

    permission view = viewer + owner
    permission edit = owner
}
```

### Relations

```zed
# Direct user relation
relation owner: user

# User or group member
relation editor: user | group#member

# Multiple types
relation parent: folder | drive

# Wildcard (public)
relation viewer: user | user:*
```

### Permissions

```zed
# Union (OR)
permission view = viewer + owner

# Intersection (AND)
permission admin_view = admin & viewer

# Exclusion (NOT)
permission non_owner_view = viewer - owner

# Arrow (traverse relationship)
permission view = viewer + parent->view

# Nested
permission edit = (editor + owner) & active_user
```

## Client Libraries

### Go

```bash
go get github.com/authzed/authzed-go
```

```go
package main

import (
    "context"
    "log"

    v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
    "github.com/authzed/authzed-go/v1"
    "github.com/authzed/grpcutil"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

func main() {
    client, err := authzed.NewClient(
        "localhost:50051",
        grpc.WithTransportCredentials(insecure.NewCredentials()),
        grpcutil.WithInsecureBearerToken("dev-key"),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Check permission
    resp, err := client.CheckPermission(context.Background(), &v1.CheckPermissionRequest{
        Resource: &v1.ObjectReference{
            ObjectType: "document",
            ObjectId:   "readme",
        },
        Permission: "view",
        Subject: &v1.SubjectReference{
            Object: &v1.ObjectReference{
                ObjectType: "user",
                ObjectId:   "alice",
            },
        },
    })

    if err != nil {
        log.Fatal(err)
    }

    if resp.Permissionship == v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION {
        log.Println("Alice can view document:readme")
    }

    // Write relationship
    _, err = client.WriteRelationships(context.Background(), &v1.WriteRelationshipsRequest{
        Updates: []*v1.RelationshipUpdate{
            {
                Operation: v1.RelationshipUpdate_OPERATION_CREATE,
                Relationship: &v1.Relationship{
                    Resource: &v1.ObjectReference{
                        ObjectType: "document",
                        ObjectId:   "readme",
                    },
                    Relation: "viewer",
                    Subject: &v1.SubjectReference{
                        Object: &v1.ObjectReference{
                            ObjectType: "user",
                            ObjectId:   "bob",
                        },
                    },
                },
            },
        },
    })
}
```

### Python

```bash
pip install authzed
```

```python
from authzed.api.v1 import (
    Client,
    CheckPermissionRequest,
    ObjectReference,
    SubjectReference,
    Relationship,
    RelationshipUpdate,
    WriteRelationshipsRequest,
)

# Create client
client = Client(
    "localhost:50051",
    "dev-key",
    insecure=True
)

# Check permission
response = client.CheckPermission(CheckPermissionRequest(
    resource=ObjectReference(
        object_type="document",
        object_id="readme"
    ),
    permission="view",
    subject=SubjectReference(
        object=ObjectReference(
            object_type="user",
            object_id="alice"
        )
    )
))

if response.permissionship == CheckPermissionResponse.PERMISSIONSHIP_HAS_PERMISSION:
    print("Alice can view document:readme")

# Write relationship
client.WriteRelationships(WriteRelationshipsRequest(
    updates=[
        RelationshipUpdate(
            operation=RelationshipUpdate.OPERATION_CREATE,
            relationship=Relationship(
                resource=ObjectReference(
                    object_type="document",
                    object_id="readme"
                ),
                relation="viewer",
                subject=SubjectReference(
                    object=ObjectReference(
                        object_type="user",
                        object_id="bob"
                    )
                )
            )
        )
    ]
))
```

### Node.js

```bash
npm install @authzed/authzed-node
```

```javascript
const { v1 } = require('@authzed/authzed-node');

const client = v1.NewClient(
    'dev-key',
    'localhost:50051',
    v1.ClientSecurity.INSECURE_PLAINTEXT_CREDENTIALS
);

// Check permission
const checkResp = await client.checkPermission({
    resource: {
        objectType: 'document',
        objectId: 'readme',
    },
    permission: 'view',
    subject: {
        object: {
            objectType: 'user',
            objectId: 'alice',
        },
    },
});

if (checkResp.permissionship === v1.CheckPermissionResponse_Permissionship.HAS_PERMISSION) {
    console.log('Alice can view document:readme');
}

// Write relationship
await client.writeRelationships({
    updates: [{
        operation: v1.RelationshipUpdate_Operation.CREATE,
        relationship: {
            resource: {
                objectType: 'document',
                objectId: 'readme',
            },
            relation: 'viewer',
            subject: {
                object: {
                    objectType: 'user',
                    objectId: 'bob',
                },
            },
        },
    }],
});
```

## Advanced Patterns

### Google Drive-Like Sharing

```zed
definition user {}

definition group {
    relation member: user
}

definition folder {
    relation owner: user
    relation editor: user | group#member
    relation viewer: user | group#member
    relation parent: folder

    permission view = viewer + editor + owner + parent->view
    permission edit = editor + owner + parent->edit
    permission delete = owner
}

definition document {
    relation owner: user
    relation editor: user | group#member
    relation viewer: user | group#member
    relation parent: folder

    permission view = viewer + editor + owner + parent->view
    permission edit = editor + owner + parent->edit
    permission delete = owner
    permission share = owner
}
```

**Usage**:
```
# Folder hierarchy
folder:root#owner@user:alice
folder:projects#parent@folder:root
document:readme#parent@folder:projects

# Direct sharing
document:readme#viewer@user:bob

# Bob can view readme because:
# 1. Direct viewer relationship
# OR
# 2. Inherits from parent folder
```

### Organization Hierarchy

```zed
definition user {}

definition organization {
    relation admin: user
    relation member: user

    permission view_billing = admin
    permission invite_users = admin
}

definition team {
    relation organization: organization
    relation admin: user
    relation member: user

    permission view = member + admin + organization->member
    permission edit = admin + organization->admin
}

definition project {
    relation team: team
    relation owner: user
    relation contributor: user

    permission view = contributor + owner + team->view
    permission edit = owner + team->edit
    permission delete = owner + team->admin
}
```

### Conditional Relations

```zed
definition document {
    relation owner: user
    relation viewer: user with expiration

    permission view = viewer + owner
}
```

## Consistency and Zookies

SpiceDB provides strong consistency via "Zookies" (ZedTokens):

```go
// Write relationship
writeResp, _ := client.WriteRelationships(ctx, writeReq)
zookie := writeResp.WrittenAt

// Read with same zookie (consistent view)
checkResp, _ := client.CheckPermission(ctx, &v1.CheckPermissionRequest{
    Resource: resource,
    Permission: "view",
    Subject: subject,
    Consistency: &v1.Consistency{
        Requirement: &v1.Consistency_AtLeastAsFresh{
            AtLeastAsFresh: zookie,
        },
    },
})
```

## Performance

### Benchmarks

- **Check Permission**: 5-20ms (with PostgreSQL)
- **Write Relationship**: 5-15ms
- **Lookup Resources**: 10-50ms
- **Throughput**: 10k-50k requests/sec per instance

### Optimization

```go
// Batch permission checks
client.CheckBulkPermissions(ctx, &v1.CheckBulkPermissionsRequest{
    Items: []*v1.CheckBulkPermissionsRequestItem{
        {Resource: doc1, Permission: "view", Subject: alice},
        {Resource: doc2, Permission: "view", Subject: alice},
        {Resource: doc3, Permission: "view", Subject: alice},
    },
})

// Cache zookies
// Reuse zookie for multiple reads in same transaction
```

## Production Deployment

### Docker Compose

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: spicedb
      POSTGRES_USER: spicedb
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  spicedb:
    image: authzed/spicedb:latest
    command: serve
    environment:
      - SPICEDB_GRPC_PRESHARED_KEY=your-secret-key
      - SPICEDB_DATASTORE_ENGINE=postgres
      - SPICEDB_DATASTORE_CONN_URI=postgres://spicedb:password@postgres:5432/spicedb?sslmode=disable
    ports:
      - "50051:50051"
      - "8080:8080"  # Metrics
    depends_on:
      - postgres
    healthcheck:
      test: ["CMD", "grpc_health_probe", "-addr=:50051"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  postgres_data:
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: spicedb
spec:
  replicas: 3
  selector:
    matchLabels:
      app: spicedb
  template:
    metadata:
      labels:
        app: spicedb
    spec:
      containers:
      - name: spicedb
        image: authzed/spicedb:latest
        args: ["serve"]
        env:
        - name: SPICEDB_GRPC_PRESHARED_KEY
          valueFrom:
            secretKeyRef:
              name: spicedb-secret
              key: preshared-key
        - name: SPICEDB_DATASTORE_ENGINE
          value: "postgres"
        - name: SPICEDB_DATASTORE_CONN_URI
          valueFrom:
            secretKeyRef:
              name: spicedb-secret
              key: datastore-uri
        ports:
        - containerPort: 50051
          name: grpc
        - containerPort: 8080
          name: metrics
        livenessProbe:
          grpc:
            port: 50051
          initialDelaySeconds: 10
        readinessProbe:
          grpc:
            port: 50051
          initialDelaySeconds: 5
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
---
apiVersion: v1
kind: Service
metadata:
  name: spicedb
spec:
  selector:
    app: spicedb
  ports:
  - name: grpc
    protocol: TCP
    port: 50051
    targetPort: 50051
  - name: metrics
    protocol: TCP
    port: 8080
    targetPort: 8080
```

## Monitoring

### Prometheus Metrics

```bash
# Scrape metrics
curl http://localhost:8080/metrics

# Key metrics:
# - spicedb_check_permission_duration_seconds
# - spicedb_lookup_resources_duration_seconds
# - spicedb_datastore_query_duration_seconds
```

## Best Practices

1. **Schema Design**: Plan schema carefully, changes are versioned
2. **Use Wildcards**: For public resources (`user:*`)
3. **Batch Operations**: Use bulk APIs when possible
4. **Cache Zookies**: Reuse for consistent reads
5. **Monitor Latency**: Track permission check times
6. **Index Relationships**: Ensure database indexes
7. **Test Schema**: Validate before production
8. **Version Schema**: Use schema versioning
9. **Backup Data**: Regular relationship backups
10. **Scale Horizontally**: Add more SpiceDB instances

## Comparison

| Feature | SpiceDB | OPA | Casbin |
|---------|---------|-----|--------|
| **Model** | ReBAC | ABAC | RBAC/ABAC |
| **Relationships** | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐ |
| **Consistency** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Performance** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Scalability** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Setup** | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

## Further Resources

- **Documentation**: [docs.authzed.com](https://docs.authzed.com/)
- **Playground**: [play.authzed.com](https://play.authzed.com/)
- **Examples**: [github.com/authzed/examples](https://github.com/authzed/examples)
- **Zanzibar Paper**: [Google Research](https://research.google/pubs/pub48190/)

## Community

- **Discord**: [authzed.com/discord](https://authzed.com/discord)
- **GitHub Discussions**: [github.com/authzed/spicedb/discussions](https://github.com/authzed/spicedb/discussions)

## Next Steps

- Review [ReBAC Concepts](../../fundamentals/concepts/rebac.md)
- Understand [Policy Making](../../fundamentals/policy-standards/policy-making.md)
- Compare with [OPA](../opa/README.md)
- Check [Comparative Analysis](../../COMPARISON.md)
