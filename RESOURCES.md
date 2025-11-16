# External Resources & References

## Overview

This curated list provides high-quality external resources for learning about authorization, access control, and related security topics. All resources are free unless marked otherwise.

---

## 🎓 Official Framework Documentation

### Open Policy Agent (OPA)
- **Official Docs**: https://www.openpolicyagent.org/docs/latest/
- **Playground**: https://play.openpolicyagent.org/
- **Styra Academy**: https://academy.styra.com/ (Free courses)
- **GitHub**: https://github.com/open-policy-agent/opa
- **Blog**: https://blog.openpolicyagent.org/
- **Slack**: https://slack.openpolicyagent.org/

### Casbin
- **Official Docs**: https://casbin.org/docs/overview
- **Online Editor**: https://casbin.org/editor
- **GitHub**: https://github.com/casbin/casbin
- **Forum**: https://forum.casbin.com/
- **Gitter**: https://gitter.im/casbin/lobby

### Keycloak
- **Official Docs**: https://www.keycloak.org/documentation
- **Blog**: https://www.keycloak.org/blog
- **GitHub**: https://github.com/keycloak/keycloak
- **Mailing List**: https://lists.jboss.org/mailman/listinfo/keycloak-user
- **Discourse**: https://keycloak.discourse.group/

### OSO (Oso Security)
- **Official Docs**: https://docs.osohq.com/
- **Guides**: https://www.osohq.com/guides
- **Academy**: https://www.osohq.com/academy
- **GitHub**: https://github.com/osohq/oso
- **Slack**: https://join-slack.osohq.com/

### SpiceDB (AuthZed)
- **Official Docs**: https://docs.authzed.com/
- **Playground**: https://play.authzed.com/
- **GitHub**: https://github.com/authzed/spicedb
- **Discord**: https://authzed.com/discord
- **Blog**: https://authzed.com/blog

### CASL
- **Official Docs**: https://casl.js.org/v6/en/
- **GitHub**: https://github.com/stalniy/casl
- **Examples**: https://github.com/stalniy/casl-examples
- **Gitter**: https://gitter.im/stalniy-casl/casl

---

## 📚 Standards & Specifications

### NIST (National Institute of Standards and Technology)
- **RBAC Model**: https://csrc.nist.gov/projects/role-based-access-control
- **ABAC Guide (SP 800-162)**: https://csrc.nist.gov/publications/detail/sp/800-162/final
- **Zero Trust (SP 800-207)**: https://csrc.nist.gov/publications/detail/sp/800-207/final
- **Access Control Guidelines**: https://csrc.nist.gov/projects/access-control

### OASIS Standards
- **XACML 3.0**: http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html
- **SAML 2.0**: https://www.oasis-open.org/committees/security/

### IETF RFCs
- **OAuth 2.0 (RFC 6749)**: https://datatracker.ietf.org/doc/html/rfc6749
- **JWT (RFC 7519)**: https://datatracker.ietf.org/doc/html/rfc7519
- **OAuth 2.0 Bearer Tokens (RFC 6750)**: https://datatracker.ietf.org/doc/html/rfc6750
- **PKCE (RFC 7636)**: https://datatracker.ietf.org/doc/html/rfc7636
- **OAuth 2.0 Security Best Practices**: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics

### OpenID Foundation
- **OpenID Connect**: https://openid.net/connect/
- **Specifications**: https://openid.net/developers/specs/

---

## 📖 Research Papers

### Foundational Papers
- **Zanzibar (Google)**: https://research.google/pubs/pub48190/
  - Google's global authorization system, inspiration for SpiceDB
- **Macaroons**: https://research.google/pubs/pub41892/
  - Decentralized authorization credentials

### Academic Resources
- **ACM Digital Library**: https://dl.acm.org/
  - Search: "access control", "authorization", "RBAC", "ABAC"
- **IEEE Xplore**: https://ieeexplore.ieee.org/
  - Security and privacy papers

---

## 🛡️ Security Resources

### OWASP (Open Web Application Security Project)
- **Top 10**: https://owasp.org/www-project-top-ten/
  - #1 is Broken Access Control
- **Authorization Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- **Session Management**: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- **JWT Security**: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html

### CISA (Cybersecurity & Infrastructure Security Agency)
- **Zero Trust Maturity Model**: https://www.cisa.gov/zero-trust-maturity-model
- **Security Guidance**: https://www.cisa.gov/cybersecurity

### CIS (Center for Internet Security)
- **Controls**: https://www.cisecurity.org/controls
  - Control 6: Access Control Management
- **Benchmarks**: https://www.cisecurity.org/cis-benchmarks/

### Cloud Security Alliance
- **Cloud Controls Matrix**: https://cloudsecurityalliance.org/research/cloud-controls-matrix/
- **Zero Trust**: https://cloudsecurityalliance.org/research/working-groups/zero-trust/

---

## 🎥 Video Tutorials & Courses

### Free Courses

**OPA/Rego**
- **Styra Academy**: https://academy.styra.com/
  - Free comprehensive OPA courses
- **YouTube - OPA Deep Dive**: https://www.youtube.com/c/Styra

**General Authorization**
- **OAuth 2.0 Simplified**: https://www.oauth.com/
- **JWT.io Introduction**: https://jwt.io/introduction

**Cloud Native**
- **CNCF YouTube**: https://www.youtube.com/c/cloudnativefdn
  - Search: "OPA", "authorization", "security"

### Paid Courses (Recommended)

**Udemy**
- OAuth 2.0 courses
- API Security courses
- Keycloak courses

**Pluralsight**
- API Security
- Identity and Access Management

**LinkedIn Learning**
- Security courses

---

## 📝 Blogs & Articles

### Company Engineering Blogs

**Airbnb**: https://medium.com/airbnb-engineering
- Search: "authorization", "permissions"

**Netflix**: https://netflixtechblog.com/
- Microservices security

**Uber**: https://eng.uber.com/
- Access control at scale

**Stripe**: https://stripe.com/blog/engineering
- API security

**Auth0 Blog**: https://auth0.com/blog/
- OAuth, JWT, authorization topics

### Individual Blogs

**Phil Booth**: https://philbooth.me/
- Authorization patterns

**Auth0 Blog**: https://auth0.com/blog/
- Identity and access management

---

## 🛠️ Tools & Libraries

### Policy Testing
- **OPA Test Framework**: Built into OPA
- **Regal**: https://github.com/StyraInc/regal
  - Rego linter

### Token Tools
- **JWT.io**: https://jwt.io/
  - Decode and verify JWTs
- **OAuth Debugger**: https://oauthdebugger.com/
  - Debug OAuth flows

### API Testing
- **Postman**: https://www.postman.com/
- **Insomnia**: https://insomnia.rest/

### Security Scanning
- **OWASP ZAP**: https://www.zaproxy.org/
- **Burp Suite**: https://portswigger.net/burp (Free community edition)

---

## 📦 Example Projects & Repositories

### OPA Examples
- **OPA Examples**: https://github.com/open-policy-agent/opa/tree/main/examples
- **Policy Library**: https://github.com/open-policy-agent/library

### Casbin Examples
- **Casbin Examples**: https://github.com/casbin/casbin/tree/master/examples
- **Casbin Samples**: https://github.com/casbin-samples

### Keycloak Examples
- **Keycloak Quickstarts**: https://github.com/keycloak/keycloak-quickstarts

### Real-World Applications
- **Kubernetes**: https://github.com/kubernetes/kubernetes
  - RBAC implementation
- **OpenFGA**: https://github.com/openfga/openfga
  - Fine-grained authorization

---

## 📚 Books

### Authorization & Access Control

**Free/Open**
- **The OPA Book**: https://www.openpolicyagent.org/docs/latest/
- **OAuth 2.0 Simplified**: https://www.oauth.com/

**Paid**
- **"OAuth 2 in Action"** by Justin Richer & Antonio Sanso
- **"Identity and Data Security for Web Development"** by Jonathan LeBlanc & Tim Messerschmidt
- **"API Security in Action"** by Neil Madden

### General Security
- **"The Web Application Hacker's Handbook"** by Dafydd Stuttard & Marcus Pinto
- **"Security Engineering"** by Ross Anderson (Free: https://www.cl.cam.ac.uk/~rja14/book.html)

---

## 🎤 Conferences & Events

### Regular Conferences

**KubeCon + CloudNativeCon**
- Topics: OPA, service mesh, cloud security
- Videos: https://www.youtube.com/c/cloudnativefdn

**OWASP AppSec**
- Application security
- https://owasp.org/events/

**RSA Conference**
- Security and access control
- https://www.rsaconference.com/

**Black Hat / DEF CON**
- Security research
- https://www.blackhat.com/

### Meetups
- **CNCF Meetups**: https://community.cncf.io/
- **OWASP Chapters**: https://owasp.org/chapters/
- **Local Security Meetups**: Search meetup.com

---

## 💬 Communities & Forums

### General

**Reddit**
- r/netsec: https://reddit.com/r/netsec
- r/security: https://reddit.com/r/security
- r/kubernetes: https://reddit.com/r/kubernetes

**Stack Overflow**
- Tags: `oauth-2.0`, `jwt`, `rbac`, `authorization`, `keycloak`, `opa`, `casbin`

**Discord/Slack Communities**
- **CNCF Slack**: https://slack.cncf.io/
- **Kubernetes Slack**: https://slack.k8s.io/
- **OPA Slack**: https://slack.openpolicyagent.org/

### Twitter/X Accounts to Follow
- **@openpolicyagent** - OPA official
- **@authzed** - SpiceDB team
- **@keycloak** - Keycloak official
- **@OWASP** - OWASP foundation
- **@CloudNativeFdn** - CNCF

---

## 🔍 Search Resources

### Google Queries
```
"authorization best practices" site:*.com
"RBAC implementation" site:github.com
"OPA tutorial" -site:openpolicyagent.org
"OAuth 2.0 security" site:tools.ietf.org
```

### GitHub Search
```
authorization language:Go stars:>100
rbac topic:authorization
policy-engine topic:kubernetes
```

### Academic Search
- **Google Scholar**: https://scholar.google.com/
- **arXiv**: https://arxiv.org/ (Computer Science → Cryptography and Security)

---

## 🏢 Vendor Resources

### Cloud Providers

**AWS**
- **IAM Best Practices**: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- **Verified Permissions**: https://aws.amazon.com/verified-permissions/

**Google Cloud**
- **IAM Overview**: https://cloud.google.com/iam/docs/overview
- **BeyondCorp**: https://cloud.google.com/beyondcorp

**Azure**
- **Azure RBAC**: https://docs.microsoft.com/en-us/azure/role-based-access-control/
- **Azure AD**: https://docs.microsoft.com/en-us/azure/active-directory/

### Identity Providers

**Okta**: https://developer.okta.com/
**Auth0**: https://auth0.com/developers
**Ping Identity**: https://www.pingidentity.com/en/resources.html

---

## 📊 Benchmarks & Comparisons

### Authorization Framework Comparisons
- **AuthZ Comparison**: https://docs.google.com/spreadsheets/d/... (Community maintained)
- **Policy Engine Benchmarks**: Check individual framework documentation

### Performance Testing
- **OPA Performance**: https://www.openpolicyagent.org/docs/latest/policy-performance/
- **Casbin Benchmarks**: https://casbin.org/docs/benchmark

---

## 🎯 Practice & Learning

### Interactive Tutorials
- **OPA Playground**: https://play.openpolicyagent.org/
- **SpiceDB Playground**: https://play.authzed.com/
- **Casbin Editor**: https://casbin.org/editor

### CTF & Challenges
- **OWASP WebGoat**: https://owasp.org/www-project-webgoat/
  - Broken access control lessons
- **HackTheBox**: https://www.hackthebox.com/
  - Authorization challenges

### Coding Practice
- **LeetCode** - System design questions
- **GitHub** - Contribute to open-source authorization projects

---

## 📰 Newsletters

**Security Newsletters**
- **OWASP Newsletter**: https://owasp.org/
- **SANS NewsBites**: https://www.sans.org/newsletters/newsbites/
- **Krebs on Security**: https://krebsonsecurity.com/

**Cloud Native**
- **CNCF Newsletter**: https://www.cncf.io/newsroom/newsletter/
- **Kubernetes Newsletter**: https://www.kubernetes.dev/resources/newsletter/

**Framework-Specific**
- **OPA Newsletter**: Subscribe via openpolicyagent.org
- **Auth0 Newsletter**: https://auth0.com/

---

## 🔗 Related Topics

### Broader Security Topics
- **Application Security**: OWASP resources
- **API Security**: API Security Top 10
- **Cloud Security**: Cloud Security Alliance
- **Zero Trust**: NIST SP 800-207

### Complementary Technologies
- **Service Mesh**: Istio, Linkerd documentation
- **API Gateways**: Kong, Tyk, Envoy docs
- **Identity**: OAuth, OIDC, SAML specs
- **Secrets Management**: HashiCorp Vault, AWS Secrets Manager

---

## 🆕 Stay Updated

### RSS Feeds
- Framework blogs (OPA, Casbin, etc.)
- Security news sites
- Cloud native news

### Podcasts
- **Security Now**: https://twit.tv/shows/security-now
- **Darknet Diaries**: https://darknetdiaries.com/
- **Kubernetes Podcast**: https://kubernetespodcast.com/

### YouTube Channels
- **CNCF**: https://www.youtube.com/c/cloudnativefdn
- **OWASP**: https://www.youtube.com/c/OWASPGLOBAL
- **Styra**: https://www.youtube.com/c/Styra

---

## 📝 Contribution

Know a great resource? [Contribute it!](./CONTRIBUTING.md)

**Criteria for inclusion**:
- High quality and accurate
- Actively maintained
- Relevant to authorization/access control
- Free or clearly marked as paid

---

## ⚠️ Disclaimer

External resources are provided for educational purposes. We don't endorse or take responsibility for external content. Always verify information and use resources responsibly.

---

**Last Updated**: 2025-11-16

**Maintained by**: Community contributions welcome!
