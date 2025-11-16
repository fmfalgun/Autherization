# Authorization Terminology Glossary

## Overview

This glossary provides definitions for common terms used in authorization systems, access control, and identity management.

---

## A

### ABAC (Attribute-Based Access Control)
An access control model that makes decisions based on attributes of users, resources, actions, and environment. More flexible than RBAC but more complex.

**Example**: "Engineers can access engineering documents during business hours from corporate network"

### Access Control
The process of granting or denying requests to obtain and use information and related resources.

### Access Control List (ACL)
A list of permissions attached to an object specifying which users or system processes can access that object.

### Access Token
A credential used to access protected resources, typically short-lived and issued after authentication.

### Actor
The entity (user, service, application) requesting access to a resource.

### Admission Control
In Kubernetes, the process of validating and potentially modifying resource requests before persistence.

### Allow List (Whitelist)
A list explicitly identifying entities that are permitted access.

### API Gateway
An entry point for API requests that can enforce authentication and authorization policies.

### Attribute
A property or characteristic of an entity (user, resource, environment) used in access decisions.

### Audit Log
A record of all authorization decisions and access attempts for compliance and security monitoring.

### Authentication (AuthN)
The process of verifying the identity of a user or system. Answers "Who are you?"

### Authorization (AuthZ)
The process of determining what an authenticated entity is allowed to do. Answers "What can you do?"

### Authorization Server
A server that issues access tokens after successfully authenticating the resource owner.

---

## B

### Bearer Token
An access token that grants access to whoever possesses it (the "bearer").

### Blacklist (Deny List)
A list of entities explicitly denied access.

### Break-Glass Access
Emergency access mechanism allowing privileged access in critical situations, with extensive logging.

### Bundle
A collection of policies and data packaged together for deployment (used in OPA).

---

## C

### CASL
Code Access Security Library - JavaScript authorization library for frontend and backend.

### Casbin
Authorization library supporting multiple access control models (ACL, RBAC, ABAC).

### Claim
A piece of information about a subject, typically found in JWT tokens.

**Example**: `{"email": "alice@example.com", "role": "admin"}`

### Client
An application making protected resource requests on behalf of the resource owner.

### Client Credentials
Authentication method where the client authenticates using its own credentials.

### Condition
A constraint that must be satisfied for a permission to be granted.

**Example**: `resource.owner == user.id`

### Context
Environmental or situational information considered in authorization decisions (time, location, device, etc.).

### CSRF (Cross-Site Request Forgery)
An attack that tricks a user into executing unwanted actions on a web application.

---

## D

### DAC (Discretionary Access Control)
Access control where the resource owner decides who can access the resource.

### Data Filtering
Automatically limiting data results based on user permissions.

### Decision Point
Where authorization decisions are made (see PDP).

### Delegation
Granting another entity the authority to act on your behalf.

### Deny by Default
Security principle where all access is denied unless explicitly allowed.

### Domain
A scope or namespace for organizing policies and resources (used in multi-tenancy).

---

## E

### Effect
The result of a policy evaluation (allow or deny).

### Enforcement Point
Where authorization decisions are enforced (see PEP).

### Entity
Any actor, resource, or object in an authorization system.

### Entitlement
A right or permission granted to a user.

### Expiration
Time when a token, session, or permission becomes invalid.

---

## F

### Federation
Linking identity management systems across organizational boundaries.

### Fine-Grained Authorization
Access control at a detailed level (specific fields, rows, or actions).

### FGAC (Fine-Grained Access Control)
See Fine-Grained Authorization.

---

## G

### Grant
The authorization workflow that results in access token issuance.

### Grant Type
The method used to obtain an access token in OAuth 2.0.

**Types**: Authorization Code, Client Credentials, Refresh Token, Implicit

### Group
A collection of users that can be assigned permissions collectively.

---

## H

### Hierarchical RBAC
RBAC model where roles can inherit permissions from other roles.

**Example**: Admin inherits Editor permissions, Editor inherits Viewer permissions

### HMAC (Hash-based Message Authentication Code)
Cryptographic technique used to verify message integrity and authenticity.

---

## I

### IAM (Identity and Access Management)
Framework of policies and technologies ensuring the right individuals access the right resources.

### Identity Provider (IdP)
Service that creates, maintains, and manages identity information.

**Examples**: Okta, Auth0, Keycloak, Azure AD

### Implicit Grant
OAuth 2.0 grant type where access token is returned directly (deprecated for security reasons).

### Inheritance
Mechanism where roles or groups inherit permissions from parent entities.

### Issuer
The entity that creates and signs tokens (typically an authorization server).

---

## J

### JTI (JWT ID)
Unique identifier for a JWT token, used to prevent replay attacks.

### JWT (JSON Web Token)
Compact, URL-safe token format for transmitting claims between parties.

**Format**: `header.payload.signature`

### JWK (JSON Web Key)
JSON data structure representing a cryptographic key.

### JWKS (JSON Web Key Set)
Set of public keys used to verify JWT signatures.

---

## K

### Keycloak
Open-source IAM solution providing authentication and authorization services.

### Kerberos
Network authentication protocol using secret-key cryptography.

---

## L

### LDAP (Lightweight Directory Access Protocol)
Protocol for accessing and maintaining distributed directory information services.

### Least Privilege
Security principle of granting minimum permissions necessary to perform a task.

---

## M

### MAC (Mandatory Access Control)
Access control where system enforces access policy regardless of user preferences.

### Matcher
Logic used to match requests against policies (in Casbin).

### MFA (Multi-Factor Authentication)
Authentication using two or more verification factors.

**Factors**: Something you know, have, are

### Microservices Authorization
Authorization patterns for distributed microservices architectures.

### Mutual TLS (mTLS)
Both client and server authenticate each other using TLS certificates.

---

## N

### Namespace
Isolated scope for organizing resources and policies.

### NIST
National Institute of Standards and Technology - publishes security standards.

---

## O

### OAuth 2.0
Industry-standard protocol for authorization and delegated access.

### Object
Resource being accessed in an authorization system.

### OIDC (OpenID Connect)
Identity layer built on top of OAuth 2.0 for authentication.

### OPA (Open Policy Agent)
General-purpose policy engine with declarative policy language (Rego).

### OSO
Authorization library with Polar policy language for application-level authorization.

### Owner
Entity that has full control over a resource.

---

## P

### PAP (Policy Administration Point)
Where policies are created and managed.

### PDP (Policy Decision Point)
Where authorization requests are evaluated against policies.

### PEP (Policy Enforcement Point)
Where authorization decisions are enforced in the system.

### Permission
Specific action allowed on a resource.

**Example**: `read:documents`, `write:users`

### PIP (Policy Information Point)
Source of attribute values used in policy evaluation.

### PKCE (Proof Key for Code Exchange)
OAuth 2.0 extension to prevent authorization code interception.

### Polar
Declarative policy language used by OSO.

### Policy
Set of rules defining authorization decisions.

### Policy as Code
Expressing authorization policies in code/configuration files.

### Principal
The authenticated entity making a request (user, service, application).

---

## R

### RBAC (Role-Based Access Control)
Access control model where permissions are assigned to roles, users assigned to roles.

### ReBAC (Relationship-Based Access Control)
Access control based on relationships between entities in a graph.

### Rego
Declarative policy language used by Open Policy Agent (OPA).

### Refresh Token
Long-lived token used to obtain new access tokens without re-authentication.

### Relation
Connection between entities in a relationship-based system.

**Example**: `alice → owner → document:123`

### Resource
Protected entity or object that requires authorization to access.

### Resource Owner
Entity capable of granting access to a protected resource.

### Resource Server
Server hosting protected resources, accepting access tokens.

### Role
Named collection of permissions.

**Example**: `admin`, `editor`, `viewer`

### Role Hierarchy
Structure where roles inherit permissions from other roles.

### RPT (Requesting Party Token)
Token containing permissions granted to requesting party (UMA).

---

## S

### SAML (Security Assertion Markup Language)
XML-based standard for exchanging authentication and authorization data.

### Scope
Permission or set of permissions requested/granted via OAuth 2.0.

**Example**: `read:email`, `write:posts`

### Separation of Duties (SoD)
Principle requiring multiple parties to complete critical tasks.

### Service Account
Non-human account used by applications/services for authentication.

### Service Mesh
Infrastructure layer handling service-to-service communication and authorization.

**Examples**: Istio, Linkerd

### Session
Temporary state maintained between user and server across multiple requests.

### Session Token
Identifier for server-side session state.

### SoD (Separation of Duties)
See Separation of Duties.

### SpiceDB
Zanzibar-inspired authorization database for relationship-based permissions.

### SSO (Single Sign-On)
Authentication scheme allowing users to access multiple applications with one set of credentials.

### Subject
Entity requesting access (user, service, application).

---

## T

### Tenant
Isolated customer/organization in a multi-tenant system.

### Token
Credential used to access protected resources.

### Token Blacklist
List of revoked tokens that should not be accepted.

### Token Introspection
Checking the validity and metadata of a token.

### TTL (Time To Live)
Duration for which a token or session remains valid.

### Tuple
In ReBAC, a representation of a relationship: `(subject, relation, object)`

**Example**: `(alice, viewer, document:readme)`

---

## U

### UMA (User-Managed Access)
OAuth-based protocol for user-controlled authorization.

### URI (Uniform Resource Identifier)
String identifying a resource (used in redirect URLs, resource identifiers).

### User
Individual person using a system.

### Userset
Set of users related to a resource (in Zanzibar/SpiceDB).

---

## V

### Verification
Process of checking token authenticity and validity.

### Viewer
Common role with read-only permissions.

---

## W

### Watcher
Component monitoring policy changes to sync across instances (Casbin).

### Webhook
HTTP callback for event notifications (can be used for authorization).

### Wildcard
Special character (*) representing "all" or "any".

**Example**: `read:*` (read everything)

---

## X

### XACML (eXtensible Access Control Markup Language)
XML-based language for expressing authorization policies.

### XSS (Cross-Site Scripting)
Injection attack where malicious scripts are injected into trusted websites.

---

## Z

### Zanzibar
Google's global authorization system, inspiration for SpiceDB.

### Zero Trust
Security model that requires verification for every access request, regardless of location.

### Zookie (ZedToken)
Consistency token in SpiceDB ensuring read-after-write consistency.

---

## Common Acronyms Quick Reference

| Acronym | Full Name |
|---------|-----------|
| **ABAC** | Attribute-Based Access Control |
| **ACL** | Access Control List |
| **AuthN** | Authentication |
| **AuthZ** | Authorization |
| **DAC** | Discretionary Access Control |
| **FGAC** | Fine-Grained Access Control |
| **IAM** | Identity and Access Management |
| **IdP** | Identity Provider |
| **JWT** | JSON Web Token |
| **LDAP** | Lightweight Directory Access Protocol |
| **MAC** | Mandatory Access Control |
| **MFA** | Multi-Factor Authentication |
| **mTLS** | Mutual TLS |
| **OAuth** | Open Authorization |
| **OIDC** | OpenID Connect |
| **OPA** | Open Policy Agent |
| **PAP** | Policy Administration Point |
| **PDP** | Policy Decision Point |
| **PEP** | Policy Enforcement Point |
| **PIP** | Policy Information Point |
| **PKCE** | Proof Key for Code Exchange |
| **RBAC** | Role-Based Access Control |
| **ReBAC** | Relationship-Based Access Control |
| **SAML** | Security Assertion Markup Language |
| **SoD** | Separation of Duties |
| **SSO** | Single Sign-On |
| **UMA** | User-Managed Access |
| **XACML** | eXtensible Access Control Markup Language |

---

## Related Resources

- [RBAC Concepts](./fundamentals/concepts/rbac.md)
- [ABAC Concepts](./fundamentals/concepts/abac.md)
- [ReBAC Concepts](./fundamentals/concepts/rebac.md)
- [OAuth 2.0 Guide](./fundamentals/tokens-sessions/oauth2.md)
- [JWT Guide](./fundamentals/tokens-sessions/jwt.md)
- [Industry Standards](./fundamentals/policy-standards/standards.md)

---

**Last Updated**: 2025-11-16
