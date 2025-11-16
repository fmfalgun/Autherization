# ReBAC (Relationship-Based Access Control)

## Overview

**Relationship-Based Access Control (ReBAC)** is an authorization model that makes access decisions based on the relationships between users and resources. Popularized by Google's Zanzibar paper, ReBAC excels at modeling complex permission scenarios found in social networks, collaborative applications, and multi-tenant systems.

## Key Concepts

### Core Principle

```
Access is granted based on relationships in a graph
```

Instead of asking "What role does this user have?", ReBAC asks:
- "What is this user's relationship to this resource?"
- "Is there a path between this user and this resource?"

### The Relationship Tuple

ReBAC represents permissions as tuples:

```
(subject, relation, object)
```

**Examples:**
```
(alice, owner, doc-123)
(bob, editor, doc-123)
(group:engineering, viewer, folder-456)
(doc-123, parent, folder-456)
```

## How ReBAC Works

### Relationship Graph

```
         owner          parent
alice ---------> doc-123 ---------> folder-456
                   ^                    ^
                   |                    |
               editor               viewer
                   |                    |
                  bob           group:engineering
```

**Access Check**: "Can Bob view doc-123?"

1. Check direct relationship: `bob → editor → doc-123` ✓
2. Editors can view, so **ALLOW**

**Access Check**: "Can Alice view folder-456?"

1. Direct relationship: `alice → owner → doc-123`
2. Traverse: `doc-123 → parent → folder-456`
3. Follow policy: owners of children can view parents ✓
4. **ALLOW**

## ReBAC Schema Example

### Google Drive-like Permissions

```yaml
# Define resource types and relations
schema:
  user: {}

  group:
    relations:
      member: [user]

  folder:
    relations:
      owner: [user, group#member]
      editor: [user, group#member]
      viewer: [user, group#member]
      parent: [folder]
    permissions:
      view: viewer + editor + owner
      edit: editor + owner
      delete: owner

  document:
    relations:
      owner: [user]
      editor: [user, group#member]
      viewer: [user, group#member]
      parent: [folder]
    permissions:
      view: viewer + editor + owner + parent->view
      edit: editor + owner + parent->edit
      delete: owner
      share: owner
```

### Relationship Tuples

```
# Direct relationships
(alice, owner, doc:readme)
(bob, editor, doc:readme)
(carol, viewer, doc:readme)

# Group relationships
(dave, member, group:engineering)
(group:engineering, viewer, folder:projects)

# Hierarchy
(doc:readme, parent, folder:projects)
```

### Permission Computation

**Query**: "Can Dave view doc:readme?"

```
1. Check direct: dave → ? → doc:readme
   → Not found

2. Check group membership: dave → member → group:engineering
   → Found

3. Check group permissions: group:engineering → viewer → folder:projects
   → Found

4. Check hierarchy: doc:readme → parent → folder:projects
   → Found

5. Compute: dave is member of engineering
            engineering can view folder:projects
            doc:readme is in folder:projects
            documents inherit parent folder permissions
   → ALLOW
```

## Implementation Example

### ReBAC in Go (Simplified)

```go
package main

import "fmt"

type Tuple struct {
    Subject  string
    Relation string
    Object   string
}

type ReBAC struct {
    tuples []Tuple
}

func (r *ReBAC) Add(subject, relation, object string) {
    r.tuples = append(r.tuples, Tuple{subject, relation, object})
}

func (r *ReBAC) Check(subject, relation, object string) bool {
    // Direct check
    for _, t := range r.tuples {
        if t.Subject == subject && t.Relation == relation && t.Object == object {
            return true
        }
    }

    // Expand based on relation definitions
    // (simplified - real implementation would be recursive)
    if relation == "view" {
        // Check if user is owner, editor, or viewer
        if r.Check(subject, "owner", object) ||
           r.Check(subject, "editor", object) ||
           r.Check(subject, "viewer", object) {
            return true
        }
    }

    return false
}

func main() {
    rebac := &ReBAC{}

    // Add relationships
    rebac.Add("alice", "owner", "doc:123")
    rebac.Add("bob", "editor", "doc:123")
    rebac.Add("carol", "viewer", "doc:123")

    // Check permissions
    fmt.Println(rebac.Check("alice", "view", "doc:123")) // true (owner can view)
    fmt.Println(rebac.Check("bob", "view", "doc:123"))   // true (editor can view)
    fmt.Println(rebac.Check("dave", "view", "doc:123"))  // false (no relationship)
}
```

### Using SpiceDB (Zanzibar-inspired)

```yaml
# Schema definition
schema: |
  definition user {}

  definition document {
    relation owner: user
    relation editor: user
    relation viewer: user

    permission view = viewer + editor + owner
    permission edit = editor + owner
    permission delete = owner
  }

# Relationship data
relationships:
  - resource: document:readme
    relation: owner
    subject: user:alice

  - resource: document:readme
    relation: editor
    subject: user:bob

  - resource: document:readme
    relation: viewer
    subject: user:carol
```

**Query** (using SpiceDB client):
```go
response, err := client.CheckPermission(ctx, &v1.CheckPermissionRequest{
    Resource: &v1.ObjectReference{
        ObjectType: "document",
        ObjectId:   "readme",
    },
    Permission: "view",
    Subject: &v1.SubjectReference{
        Object: &v1.ObjectReference{
            ObjectType: "user",
            ObjectId:   "bob",
        },
    },
})
// response.Permissionship == PERMISSIONSHIP_HAS_PERMISSION
```

## Advantages

✅ **Natural Modeling**: Intuitive for social/collaborative apps
✅ **Flexible**: Handles complex relationship scenarios
✅ **Scalable**: Efficient graph traversal algorithms
✅ **Hierarchical**: Built-in support for nested resources
✅ **Fine-Grained**: Precise control over individual resources
✅ **Auditable**: Clear relationship trails

## Disadvantages

❌ **Complexity**: Requires graph database or specialized system
❌ **Performance**: Graph traversal can be expensive
❌ **Learning Curve**: New mental model vs RBAC
❌ **Tooling**: Fewer mature tools compared to RBAC
❌ **Consistency**: Distributed graph consistency challenges

## Use Cases

### Best For:
- Social networks (Facebook, LinkedIn)
- Collaborative tools (Google Drive, Notion)
- Multi-tenant SaaS applications
- Hierarchical resource structures
- Sharing and delegation scenarios

### Real-World Examples:

**1. Google Drive**
```
User can access document if:
  - Direct viewer/editor/owner
  - Member of group with access
  - Document's parent folder grants access
  - Shared via link with appropriate permissions
```

**2. GitHub Repository Access**
```
User can push to repo if:
  - Direct collaborator
  - Member of team with write access
  - Owner of organization
  - Repository is public (for read)
```

**3. Slack Workspace**
```
User can read channel if:
  - Member of channel
  - Member of workspace (for public channels)
  - Admin of workspace
```

## ReBAC vs RBAC vs ABAC

| Aspect | ReBAC | RBAC | ABAC |
|--------|-------|------|------|
| **Model** | Graph-based | Role-based | Attribute-based |
| **Granularity** | Per-resource | Per-role | Fine-grained |
| **Flexibility** | High | Low | Very High |
| **Complexity** | Medium-High | Low | High |
| **Performance** | Medium | Fast | Slower |
| **Context** | Relationships | Static | Fully dynamic |
| **Best For** | Sharing, collaboration | Enterprises | Complex rules |

## Zanzibar Paper

Google's **Zanzibar** paper (2019) introduced ReBAC at scale:

### Key Innovations:

1. **Relation Tuples**: `(object, relation, subject)`
2. **Namespaces**: Type system for objects
3. **Userset Rewrites**: Define permissions from relations
4. **Consistency**: Snapshot reads with Zookies
5. **Scale**: Billions of ACLs, millions of QPS

### Zanzibar-Inspired Systems:
- **SpiceDB** (AuthZed)
- **Ory Keto**
- **OpenFGA** (Auth0)
- **Permify**
- **Warrant**

## Common Patterns

### 1. Ownership
```
(alice, owner, doc:123)
permission delete = owner
```

### 2. Inheritance
```
(doc:123, parent, folder:456)
(alice, viewer, folder:456)
# Alice can view doc:123 through parent relationship
permission view = viewer + parent->viewer
```

### 3. Group Membership
```
(alice, member, group:engineering)
(group:engineering#member, viewer, doc:123)
# Alice can view through group membership
```

### 4. Delegation
```
(alice, owner, doc:123)
(bob, delegate_of, alice)
# Bob inherits alice's permissions
permission edit = owner + owner->delegate_of
```

### 5. Conditional Relations
```
(alice, conditional_viewer, doc:123)
condition: time < expiry_time
# Time-limited access
```

## Schema Design Best Practices

1. **Start with Resources**: Define your object types first
2. **Model Relationships**: What connections exist?
3. **Define Permissions**: Compute from relations
4. **Use Indirection**: `group#member` for scalability
5. **Plan for Hierarchy**: Parent-child relationships
6. **Version Schemas**: Track changes over time
7. **Test Exhaustively**: All permission scenarios

## Example: Multi-Tenant SaaS

```yaml
schema: |
  definition user {}

  definition organization {
    relation admin: user
    relation member: user

    permission invite = admin
    permission view_billing = admin
  }

  definition project {
    relation organization: organization
    relation owner: user
    relation contributor: user

    permission view = contributor + owner + organization->member
    permission edit = owner + organization->admin
    permission delete = owner + organization->admin
  }

  definition resource {
    relation project: project
    relation creator: user

    permission view = creator + project->view
    permission edit = creator + project->edit
    permission delete = creator + project->delete
  }
```

**Relationships**:
```
(alice, admin, org:acme)
(bob, member, org:acme)
(project:website, organization, org:acme)
(carol, owner, project:website)
(resource:logo, project, project:website)
(dave, creator, resource:logo)
```

**Query**: "Can Alice delete resource:logo?"
```
1. alice → admin → org:acme
2. project:website → organization → org:acme
3. resource:logo → project → project:website
4. resource.delete = creator + project->delete
5. project->delete = owner + organization->admin
6. alice is admin of org, org owns project, project owns resource
→ ALLOW
```

## Performance Considerations

### Optimization Techniques:

1. **Caching**: Cache frequent checks
2. **Materialized Paths**: Pre-compute common paths
3. **Indexing**: Index tuples by subject and object
4. **Batching**: Batch permission checks
5. **Denormalization**: Store computed permissions
6. **Sharding**: Distribute graph across nodes

### Benchmark Expectations:
- **SpiceDB**: 10k-100k checks/sec per node
- **Ory Keto**: 5k-50k checks/sec
- **Latency**: p95 < 10ms for simple checks

## Tools and Frameworks

### Production-Ready:
- **SpiceDB**: Most mature, high performance
- **OpenFGA**: Auth0-backed, good docs
- **Ory Keto**: Part of Ory ecosystem
- **Permify**: Developer-friendly

### Evaluation:
- **Warrant**: Simple API
- **Authz**: Open source alternative

## Migration Strategy

### From RBAC to ReBAC:

1. **Map Roles to Relations**
   ```
   RBAC: user has role "editor"
   ReBAC: (user, editor, resource)
   ```

2. **Add Resource Specificity**
   ```
   RBAC: global "editor" role
   ReBAC: editor of specific documents
   ```

3. **Introduce Hierarchies**
   ```
   folder → document relationships
   ```

4. **Phase Implementation**
   - Phase 1: Direct relationships only
   - Phase 2: Add groups
   - Phase 3: Add hierarchy
   - Phase 4: Full graph

## Standards and References

- **Google Zanzibar Paper**: [Research paper](https://research.google/pubs/pub48190/)
- **Ory Keto Spec**: Based on Zanzibar
- **OpenFGA**: [Fine-Grained Authorization](https://openfga.dev/)

## Further Reading

- [Zanzibar: Google's Consistent, Global Authorization System](https://research.google/pubs/pub48190/)
- [SpiceDB Documentation](https://docs.authzed.com/)
- [OpenFGA Docs](https://openfga.dev/docs)
- [Ory Keto Documentation](https://www.ory.sh/docs/keto)

## Next Steps

- Compare with [RBAC](./rbac.md) and [ABAC](./abac.md)
- Explore [SpiceDB framework](../../frameworks/spicedb/)
- Learn about [Policy Making](../policy-standards/policy-making.md)
- Understand [Zero Trust](./zero-trust.md) principles
