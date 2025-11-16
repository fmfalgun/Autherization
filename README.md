# Authorization Frameworks - Comprehensive Learning Guide

> A comprehensive resource for understanding authorization systems, frameworks, and fundamental concepts

## 📋 Overview

This repository serves as a complete learning guide for **authorization** (access control and permissions management) covering open-source frameworks, fundamental concepts, technologies, and comparative analysis.

**Focus:** Authorization only (not authentication)

---

## 🗂️ Repository Structure

### 1. [Frameworks](./frameworks/)
Deep-dive into open-source authorization frameworks with implementation guides, examples, and best practices.

- **[OPA (Open Policy Agent)](./frameworks/opa/)** - Policy-based access control using Rego
- **[Casbin](./frameworks/casbin/)** - Access control library supporting multiple models
- **[Keycloak](./frameworks/keycloak/)** - Identity and access management solution
- **[OSO](./frameworks/oso/)** - Authorization library with declarative policies
- **[SpiceDB](./frameworks/spicedb/)** - Zanzibar-inspired permissions database
- **[CASL](./frameworks/casl/)** - JavaScript authorization library
- **And more...**

### 2. [Fundamentals](./fundamentals/)
Core concepts, technologies, and standards essential for understanding authorization systems.

#### [Concepts](./fundamentals/concepts/)
- [RBAC (Role-Based Access Control)](./fundamentals/concepts/rbac.md)
- [ABAC (Attribute-Based Access Control)](./fundamentals/concepts/abac.md)
- [ReBAC (Relationship-Based Access Control)](./fundamentals/concepts/rebac.md)
- [Zero Trust Architecture](./fundamentals/concepts/zero-trust.md)

#### [Technologies](./fundamentals/technologies/)
- [Rego (OPA Policy Language)](./fundamentals/technologies/rego.md)
- [YAML Fundamentals](./fundamentals/technologies/yaml.md)
- [Docker for Authorization Services](./fundamentals/technologies/docker.md)
- [Go Programming for Authorization](./fundamentals/technologies/go.md)

#### [Policy Standards](./fundamentals/policy-standards/)
- [Policy Making Techniques](./fundamentals/policy-standards/policy-making.md)
- [Industry Standards](./fundamentals/policy-standards/standards.md)

#### [Tokens & Sessions](./fundamentals/tokens-sessions/)
- [OAuth 2.0](./fundamentals/tokens-sessions/oauth2.md)
- [JWT (JSON Web Tokens)](./fundamentals/tokens-sessions/jwt.md)
- [Token Management](./fundamentals/tokens-sessions/tokens.md)
- [Session Management](./fundamentals/tokens-sessions/session-management.md)

### 3. [Comparative Analysis](./COMPARISON.md)
Detailed comparison of all frameworks across multiple dimensions:
- Performance
- Ease of use
- Policy language
- Use cases
- Scalability
- Community support
- Integration capabilities

---

## 🎯 What is Authorization?

**Authorization** determines what an authenticated user is allowed to do. It answers questions like:
- Can this user view this document?
- Does this service have permission to access that database?
- Is this role allowed to perform this action?

**Key Distinction:**
- **Authentication** = "Who are you?" (Identity verification)
- **Authorization** = "What can you do?" (Access control)

---

## 🚀 Quick Start

1. **Learn Fundamentals First:**
   - Start with [RBAC concepts](./fundamentals/concepts/rbac.md)
   - Understand [policy-making techniques](./fundamentals/policy-standards/policy-making.md)

2. **Choose a Framework:**
   - Review [comparative analysis](./COMPARISON.md)
   - Pick framework based on your use case

3. **Follow Framework Guide:**
   - Each framework directory contains setup instructions
   - Includes code examples and demos
   - Links to official documentation

---

## 📊 Framework Selection Guide

| Use Case | Recommended Framework |
|----------|----------------------|
| Cloud-native policies | OPA |
| Multi-language support | Casbin |
| Enterprise IAM | Keycloak |
| Application-level | OSO, CASL |
| Google-scale permissions | SpiceDB |

---

## 🤝 Contributing

This is a learning repository. Contributions, corrections, and suggestions are welcome!

---

## 📚 Additional Resources

- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [NIST Access Control Guidelines](https://csrc.nist.gov/projects/access-control)

---

## 📝 License

Educational resource - free to use and learn from.

---

**Author:** Falgun Marothia
**GitHub:** [@fmfalgun](https://github.com/fmfalgun)
**Purpose:** Learning about authorization frameworks comprehensively
