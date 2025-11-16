# ABAC (Attribute-Based Access Control)

## Overview

**Attribute-Based Access Control (ABAC)** is a dynamic authorization model that evaluates access decisions based on attributes of users, resources, actions, and environmental context. Unlike RBAC's fixed role assignments, ABAC provides fine-grained, context-aware access control.

## Key Concepts

### Core Components

```
Decision = f(User Attributes, Resource Attributes, Action, Environment Attributes)
```

**Four Attribute Categories:**

1. **Subject Attributes**: User properties
   - `user.department = "engineering"`
   - `user.clearance_level = "secret"`
   - `user.employment_type = "contractor"`

2. **Resource Attributes**: Object properties
   - `document.classification = "confidential"`
   - `file.owner = "alice@example.com"`
   - `data.region = "eu-west-1"`

3. **Action Attributes**: Operation being performed
   - `action = "read"`
   - `action = "delete"`
   - `action.method = "POST"`

4. **Environment Attributes**: Contextual factors
   - `time.hour >= 9 AND time.hour <= 17` (business hours)
   - `request.ip_address in corporate_network`
   - `location.country = "USA"`

## How ABAC Works

### Access Decision Flow

```
┌─────────────┐
│   Request   │
│ (User wants │
│  to access  │
│  resource)  │
└──────┬──────┘
       │
       v
┌─────────────────────────────────────┐
│  Policy Decision Point (PDP)         │
│  Evaluates attributes against rules  │
└──────┬──────────────────────────────┘
       │
       v
┌─────────────┐
│   Policy    │ ← Attributes from:
│ Evaluation  │   • User store
│             │   • Resource metadata
└──────┬──────┘   • Environment context
       │
       v
    Allow / Deny
```

## ABAC Policy Examples

### Example 1: Document Access

**Policy**: Engineers can read technical documents during business hours

```json
{
  "policy": "engineer_doc_access",
  "effect": "allow",
  "conditions": {
    "all": [
      {
        "subject.department": "engineering"
      },
      {
        "resource.type": "technical_document"
      },
      {
        "action": "read"
      },
      {
        "environment.time": {
          "between": ["09:00", "17:00"]
        }
      }
    ]
  }
}
```

### Example 2: Data Sovereignty

**Policy**: EU data can only be accessed from EU regions

```yaml
policy:
  name: eu_data_sovereignty
  effect: allow
  conditions:
    - resource.data_region == "EU"
    - action in ["read", "write"]
    - environment.request_origin_region == "EU"
```

### Example 3: Owner-Based Access

**Policy**: Users can delete their own files

```rego
# Rego (OPA policy language)
allow {
    input.action == "delete"
    input.resource.type == "file"
    input.resource.owner == input.user.id
}
```

## Implementation Example

### ABAC in Go

```go
package main

import (
    "fmt"
    "time"
)

type Attributes map[string]interface{}

type Policy struct {
    Name       string
    Conditions func(Attributes) bool
}

func evaluateABAC(user, resource, env Attributes, action string, policies []Policy) bool {
    combined := Attributes{
        "user":        user,
        "resource":    resource,
        "action":      action,
        "environment": env,
    }

    for _, policy := range policies {
        if policy.Conditions(combined) {
            fmt.Printf("Access granted by policy: %s\n", policy.Name)
            return true
        }
    }
    return false
}

func main() {
    // Define policy: Engineers can access tech docs during business hours
    techDocPolicy := Policy{
        Name: "engineer_tech_doc_access",
        Conditions: func(attrs Attributes) bool {
            user := attrs["user"].(Attributes)
            resource := attrs["resource"].(Attributes)
            env := attrs["environment"].(Attributes)
            action := attrs["action"].(string)

            hour := env["hour"].(int)
            return user["department"] == "engineering" &&
                resource["type"] == "tech_doc" &&
                action == "read" &&
                hour >= 9 && hour <= 17
        },
    }

    // Test access request
    user := Attributes{"department": "engineering", "name": "Alice"}
    resource := Attributes{"type": "tech_doc", "id": "doc-123"}
    env := Attributes{"hour": 14}

    allowed := evaluateABAC(user, resource, env, "read", []Policy{techDocPolicy})
    fmt.Printf("Access allowed: %v\n", allowed)
}
```

### ABAC with XACML-like Structure

```xml
<Policy PolicyId="medical_record_access">
  <Target>
    <Subject>
      <Attribute AttributeId="role">doctor</Attribute>
    </Subject>
    <Resource>
      <Attribute AttributeId="type">medical_record</Attribute>
    </Resource>
    <Action>
      <Attribute AttributeId="action">read</Attribute>
    </Action>
  </Target>
  <Condition>
    <Apply FunctionId="and">
      <Apply FunctionId="equal">
        <AttributeValue>subject.hospital</AttributeValue>
        <AttributeValue>resource.hospital</AttributeValue>
      </Apply>
      <Apply FunctionId="equal">
        <AttributeValue>subject.active_shift</AttributeValue>
        <AttributeValue>true</AttributeValue>
      </Apply>
    </Apply>
  </Condition>
  <Effect>Permit</Effect>
</Policy>
```

## Advantages

✅ **Fine-Grained Control**: Extremely precise access rules
✅ **Dynamic**: Adapts to changing contexts automatically
✅ **Flexible**: Handles complex scenarios easily
✅ **Context-Aware**: Considers time, location, device, etc.
✅ **Reduces Admin Overhead**: No role explosion problem
✅ **Compliance**: Meets strict regulatory requirements (GDPR, HIPAA)

## Disadvantages

❌ **Complexity**: Hard to design and maintain policies
❌ **Performance**: Attribute evaluation can be slow
❌ **Debugging**: Difficult to trace why access was denied
❌ **Attribute Management**: Requires robust attribute infrastructure
❌ **Learning Curve**: Steep for developers and administrators

## Use Cases

### Best For:
- Multi-tenant SaaS applications
- Healthcare systems (patient privacy)
- Financial services (data sovereignty)
- Government/defense (clearance levels)
- IoT systems (context-based access)

### Real-World Examples:

1. **Healthcare**: Doctor can view patient records only if:
   - Same hospital
   - Currently on shift
   - Patient assigned to doctor
   - Access from hospital network

2. **Cloud Storage**: User can access file if:
   - Owner OR member of shared group
   - File not archived
   - Access from approved device
   - MFA completed within last hour

3. **Financial System**: Approve transaction if:
   - User has approval authority
   - Transaction amount < user limit
   - During business hours
   - Not on vacation
   - From corporate IP

## ABAC vs RBAC vs ReBAC

| Aspect | ABAC | RBAC | ReBAC |
|--------|------|------|-------|
| **Granularity** | Very fine | Coarse | Medium-Fine |
| **Context** | Fully context-aware | No context | Limited context |
| **Scalability** | High (no role explosion) | Medium | High |
| **Complexity** | High | Low | Medium |
| **Performance** | Slower (runtime evaluation) | Fast (pre-computed) | Medium |
| **Use Case** | Dynamic, complex rules | Stable hierarchies | Social graphs, relationships |
| **Examples** | Healthcare, Finance | Enterprise apps | Google Drive, Facebook |

## Best Practices

1. **Start Simple**: Begin with basic attributes, add complexity gradually
2. **Centralize Attributes**: Single source of truth for attribute data
3. **Cache Decisions**: Cache policy evaluations when possible
4. **Audit Everything**: Log all access decisions with full context
5. **Test Thoroughly**: Use policy testing frameworks
6. **Document Policies**: Clear descriptions of what each policy does
7. **Version Policies**: Track policy changes over time
8. **Monitor Performance**: Watch for slow attribute lookups
9. **Fail Secure**: Default to deny if attribute lookup fails
10. **Use Policy Simulator**: Test policies before deploying

## Policy Languages for ABAC

### 1. **XACML** (eXtensible Access Control Markup Language)
- XML-based standard
- Verbose but comprehensive
- Industry standard for complex ABAC

### 2. **Rego** (OPA's language)
- Modern, declarative
- Easy to read and write
- Great for cloud-native

### 3. **Cedar** (AWS's policy language)
- Type-safe
- Validates policies at authoring time
- Used in AWS Verified Permissions

### 4. **JSON-based** (Custom)
- Easy to integrate
- Language-agnostic
- Common in REST APIs

## Common Patterns

### 1. Ownership Pattern
```rego
allow {
    input.resource.owner == input.user.id
}
```

### 2. Time-Based Access
```rego
allow {
    input.action == "read"
    hour := time.clock(time.now_ns())[0]
    hour >= 9
    hour <= 17
}
```

### 3. Multi-Condition
```rego
allow {
    # Must satisfy ALL conditions
    input.user.department == "finance"
    input.resource.classification == "internal"
    input.environment.network == "corporate"
    input.action in ["read", "write"]
}
```

### 4. Location-Based
```rego
allow {
    input.user.clearance >= input.resource.classification_level
    input.environment.location in ["US", "UK", "CA"]
}
```

## Standards and Specifications

- **XACML 3.0**: OASIS standard for ABAC
- **NIST SP 800-162**: Guide to ABAC Definition and Considerations
- **ISO/IEC 10181-3**: Access control framework
- **ALFA**: Abbreviated Language for Authorization (simplified XACML)

## Tools Implementing ABAC

- **OPA (Open Policy Agent)**: Cloud-native ABAC with Rego
- **AWS Verified Permissions**: Managed ABAC with Cedar
- **Axiomatics**: Enterprise ABAC platform
- **PlainID**: Policy-based authorization
- **AuthZed**: Relationship + attribute-based
- **Cerbos**: Application-level ABAC

## Migration from RBAC to ABAC

### Step-by-Step Approach:

1. **Map Roles to Attributes**
   ```
   RBAC: role = "editor"
   ABAC: user.permissions contains "edit"
   ```

2. **Identify Contextual Requirements**
   - What context matters? (time, location, device)

3. **Define Attribute Schema**
   - Document all attributes and their types

4. **Implement Hybrid** (RBAC + ABAC)
   - Use RBAC for basic permissions
   - Add ABAC for contextual rules

5. **Gradual Migration**
   - Start with new features in ABAC
   - Migrate existing features incrementally

## Further Reading

- [NIST ABAC Guide (SP 800-162)](https://csrc.nist.gov/publications/detail/sp/800-162/final)
- [XACML 3.0 Specification](http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html)
- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [AWS Cedar Policy Language](https://docs.cedarpolicy.com/)

## Next Steps

- Compare with [RBAC](./rbac.md) and [ReBAC](./rebac.md)
- Learn [Rego policy language](../technologies/rego.md)
- Explore [Policy Making Techniques](../policy-standards/policy-making.md)
- See [OPA framework](../../frameworks/opa/) for ABAC implementation
