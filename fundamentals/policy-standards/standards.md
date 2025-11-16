# Authorization Industry Standards and Specifications

## Overview

This document covers industry standards, specifications, and frameworks for authorization systems. Understanding these standards ensures compliance, interoperability, and adherence to best practices.

## Core Standards

### 1. NIST Standards

#### NIST SP 800-162: ABAC Guide
- **Purpose**: Guide to Attribute-Based Access Control
- **Scope**: ABAC definitions, considerations, architecture
- **Key Points**:
  - Subject, object, and environment attributes
  - Policy decision and enforcement points
  - ABAC vs RBAC comparison

**Link**: [NIST SP 800-162](https://csrc.nist.gov/publications/detail/sp/800-162/final)

#### NIST SP 800-207: Zero Trust Architecture
- **Purpose**: Zero Trust framework and principles
- **Scope**: Architecture, deployment models, use cases
- **Key Components**:
  - Policy Engine (PE)
  - Policy Administrator (PA)
  - Policy Enforcement Point (PEP)

**Link**: [NIST SP 800-207](https://csrc.nist.gov/publications/detail/sp/800-207/final)

#### NIST RBAC Model
- **Purpose**: Standard RBAC reference model
- **Levels**:
  - RBAC0: Flat RBAC
  - RBAC1: Hierarchical RBAC
  - RBAC2: Constrained RBAC
  - RBAC3: Symmetric RBAC

**Link**: [NIST RBAC](https://csrc.nist.gov/projects/role-based-access-control)

### 2. ANSI/INCITS Standards

#### ANSI INCITS 359-2004: RBAC
- **Purpose**: American National Standard for RBAC
- **Scope**: Reference model and functional specification
- **Status**: Approved ANSI standard
- **Adoption**: Widely used in enterprise systems

### 3. XACML (eXtensible Access Control Markup Language)

#### OASIS XACML 3.0
- **Purpose**: XML-based access control policy language
- **Features**:
  - Attribute-based policies
  - Policy combining algorithms
  - Obligations and advice
- **Components**:
  - Policy language
  - Request/response format
  - Architecture (PEP, PDP, PIP, PAP)

```xml
<!-- XACML Policy Example -->
<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
        PolicyId="ExamplePolicy"
        RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">
  <Target>
    <AnyOf>
      <AllOf>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
          <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">read</AttributeValue>
          <AttributeDesignator
              AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id"
              DataType="http://www.w3.org/2001/XMLSchema#string"
              MustBePresent="true"/>
        </Match>
      </AllOf>
    </AnyOf>
  </Target>
  <Rule RuleId="ReadRule" Effect="Permit">
    <Condition>
      <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
        <AttributeDesignator
            AttributeId="urn:oasis:names:tc:xacml:1.0:subject:role"
            DataType="http://www.w3.org/2001/XMLSchema#string"/>
        <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">viewer</AttributeValue>
      </Apply>
    </Condition>
  </Rule>
</Policy>
```

**Link**: [OASIS XACML](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=xacml)

### 4. OAuth 2.0 & OpenID Connect

#### OAuth 2.0 (RFC 6749)
- **Purpose**: Authorization framework
- **Use Case**: Delegated authorization
- **Grant Types**:
  - Authorization Code
  - Implicit
  - Resource Owner Password
  - Client Credentials

**Link**: [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)

#### OAuth 2.0 Scopes
Defines permission scopes for resource access.

```json
{
  "scopes": {
    "read:documents": "Read documents",
    "write:documents": "Create and modify documents",
    "delete:documents": "Delete documents",
    "admin:users": "Manage users"
  }
}
```

#### OpenID Connect
- **Purpose**: Authentication layer on OAuth 2.0
- **ID Token**: JWT containing user identity
- **UserInfo Endpoint**: Retrieve user claims

**Link**: [OpenID Connect](https://openid.net/connect/)

### 5. SAML (Security Assertion Markup Language)

#### SAML 2.0
- **Purpose**: XML-based authentication and authorization
- **Use Case**: Enterprise SSO
- **Components**:
  - Identity Provider (IdP)
  - Service Provider (SP)
  - Assertions

```xml
<!-- SAML Assertion with Authorization Decision -->
<saml:Assertion>
  <saml:AuthzDecisionStatement
      Resource="https://api.example.com/data"
      Decision="Permit">
    <saml:Action>read</saml:Action>
  </saml:AuthzDecisionStatement>
</saml:Assertion>
```

**Link**: [OASIS SAML](https://www.oasis-open.org/committees/security/)

### 6. UMA (User-Managed Access)

#### UMA 2.0
- **Purpose**: User-controlled authorization
- **Use Case**: Privacy-preserving resource sharing
- **Flow**:
  1. Resource registration
  2. Permission requests
  3. Authorization grants

**Link**: [UMA Specification](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html)

## Cloud Provider Standards

### AWS IAM

#### Policy Structure
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3Read",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:user/alice"
      },
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/*"
      ],
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "203.0.113.0/24"
        }
      }
    }
  ]
}
```

**Link**: [AWS IAM Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html)

### Google Cloud IAM

#### Policy Format
```yaml
bindings:
  - role: roles/storage.objectViewer
    members:
      - user:alice@example.com
      - serviceAccount:my-service@project.iam.gserviceaccount.com
    condition:
      title: "Expires in 2025"
      expression: "request.time < timestamp('2025-12-31T23:59:59Z')"
```

**Link**: [Google Cloud IAM](https://cloud.google.com/iam/docs/overview)

### Azure RBAC

#### Role Assignment
```json
{
  "properties": {
    "roleDefinitionId": "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/{roleId}",
    "principalId": "{principalId}",
    "scope": "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}"
  }
}
```

**Link**: [Azure RBAC](https://docs.microsoft.com/en-us/azure/role-based-access-control/)

## Kubernetes Authorization

### RBAC API

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "watch", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: default
subjects:
- kind: User
  name: jane
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

**Link**: [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

### Admission Control

- **ValidatingAdmissionWebhook**: Validate requests
- **MutatingAdmissionWebhook**: Modify requests
- **OPA Gatekeeper**: Policy-based admission control

## Compliance Standards

### 1. SOX (Sarbanes-Oxley)

**Requirements**:
- Separation of duties
- Audit trails
- Access controls for financial data

**Authorization Impact**:
- Role-based access control
- Approval workflows
- Change audit logging

### 2. HIPAA (Health Insurance Portability and Accountability Act)

**Requirements**:
- Minimum necessary access
- Role-based permissions
- Audit logs
- Encryption

**Authorization Impact**:
- Patient data access controls
- Break-glass procedures
- Access logging and monitoring

### 3. GDPR (General Data Protection Regulation)

**Requirements**:
- Data minimization
- Purpose limitation
- Access controls
- Right to access

**Authorization Impact**:
- Attribute-based access (purpose)
- Data sovereignty (location-based)
- Consent-based access
- Audit trails

### 4. PCI DSS (Payment Card Industry Data Security Standard)

**Requirements**:
- Restrict access by business need
- Assign unique IDs
- Multi-factor authentication
- Log access to cardholder data

**Authorization Impact**:
- RBAC for card data
- MFA for privileged access
- Comprehensive audit logs

### 5. FedRAMP (Federal Risk and Authorization Management Program)

**Requirements**:
- NIST 800-53 controls
- Least privilege
- Separation of duties
- Access reviews

**Authorization Impact**:
- Formal access control policies
- Regular access reviews
- Privileged access management

## API Security Standards

### 1. JSON Web Tokens (JWT) - RFC 7519

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "1234567890",
    "name": "Alice",
    "role": "admin",
    "permissions": ["read", "write", "delete"],
    "iat": 1516239022,
    "exp": 1516242622
  }
}
```

**Link**: [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)

### 2. API Key Management

**Standards**:
- OWASP API Security Top 10
- Rotation policies
- Scoped permissions

### 3. mTLS (Mutual TLS)

- Certificate-based authentication
- Service-to-service security
- Zero Trust networking

## Industry Best Practices

### OWASP

#### OWASP Top 10 (Broken Access Control - #1)

**Recommendations**:
- Deny by default
- Implement access controls once
- Enforce record ownership
- Disable directory listing
- Log access control failures

**Link**: [OWASP Top 10](https://owasp.org/www-project-top-ten/)

#### OWASP Authorization Cheat Sheet

**Key Points**:
- Enforce authorization on every request
- Use established frameworks
- Deny by default
- Validate on server side
- Log authorization failures

**Link**: [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

### CIS Controls

#### CIS Control 6: Access Control Management

- Account management
- Access control for remote access
- MFA
- Service account restrictions

**Link**: [CIS Controls](https://www.cisecurity.org/controls)

### ISO/IEC Standards

#### ISO/IEC 27001: Information Security

**Access Control (A.9)**:
- Business requirement for access control
- User access management
- User responsibilities
- System and application access control

#### ISO/IEC 29146: Access Management Framework

- Framework for access management
- Identity and access lifecycle
- Governance and accountability

## Emerging Standards

### 1. Cedar (AWS)

Amazon's policy language for authorization.

```cedar
permit(
  principal == User::"alice",
  action == Action::"view",
  resource in Folder::"documents"
);
```

**Link**: [Cedar Policy Language](https://www.cedarpolicy.com/)

### 2. Zanzibar

Google's relationship-based access control model.

**Key Concepts**:
- Relation tuples
- Namespace configuration
- Consistency tokens (Zookies)

**Implementations**: SpiceDB, OpenFGA, Ory Keto

### 3. SPIFFE/SPIRE

Secure Production Identity Framework for Everyone.

**Purpose**: Workload identity and authentication
**Use Case**: Zero Trust service-to-service authentication

**Link**: [SPIFFE](https://spiffe.io/)

## Standard Comparison

| Standard | Type | Use Case | Complexity | Adoption |
|----------|------|----------|------------|----------|
| RBAC (NIST) | Model | Enterprise IAM | Low | Very High |
| ABAC (NIST SP 800-162) | Model | Fine-grained control | High | Medium |
| XACML | Language | Policy expression | High | Medium |
| OAuth 2.0 | Protocol | Delegation | Medium | Very High |
| SAML | Protocol | Enterprise SSO | High | High |
| Zanzibar | Model | Relationship-based | Medium | Growing |
| Cedar | Language | Modern policies | Medium | Growing |

## Implementation Checklist

- [ ] Choose appropriate model (RBAC, ABAC, ReBAC)
- [ ] Follow principle of least privilege
- [ ] Implement default deny
- [ ] Use standard protocols (OAuth, SAML)
- [ ] Ensure compliance with regulations
- [ ] Implement comprehensive logging
- [ ] Regular access reviews
- [ ] MFA for privileged access
- [ ] Encryption in transit and at rest
- [ ] Incident response procedures

## Further Reading

- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [Cloud Security Alliance](https://cloudsecurityalliance.org/)
- [Zanzibar Paper](https://research.google/pubs/pub48190/)

## Next Steps

- Review [Policy Making Techniques](./policy-making.md)
- Understand [RBAC](../concepts/rbac.md), [ABAC](../concepts/abac.md), [ReBAC](../concepts/rebac.md)
- Explore framework implementations in [frameworks](../../frameworks/)
- Learn [Rego](../technologies/rego.md) for policy implementation
