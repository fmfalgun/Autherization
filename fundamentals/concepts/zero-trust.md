# Zero Trust Architecture

## Overview

**Zero Trust** is a security model based on the principle: **"Never trust, always verify."** Unlike traditional perimeter-based security, Zero Trust assumes breach and verifies every access request regardless of location.

## Core Principles

### The Three Pillars

1. **Verify Explicitly**
   - Always authenticate and authorize
   - Use all available data points (identity, location, device, service, etc.)
   - Make access decisions dynamically

2. **Use Least Privilege Access**
   - Just-In-Time (JIT) access
   - Just-Enough-Access (JEA)
   - Risk-based adaptive policies

3. **Assume Breach**
   - Minimize blast radius
   - Segment access by network, user, device, application
   - Verify end-to-end encryption
   - Use analytics for threat detection

## Traditional vs Zero Trust

### Traditional Perimeter Model

```
┌─────────────────────────────────────┐
│       Corporate Network             │
│  (Inside = Trusted)                 │
│                                     │
│  ┌──────┐  ┌──────┐  ┌──────┐     │
│  │ App  │  │ DB   │  │Files │     │
│  └──────┘  └──────┘  └──────┘     │
│                                     │
└─────────────────────────────────────┘
        Firewall (The wall)
┌─────────────────────────────────────┐
│     Internet (Untrusted)            │
└─────────────────────────────────────┘
```

**Problem**: Once inside, lateral movement is easy

### Zero Trust Model

```
Every request verified
       ↓
┌──────────────┐
│   User/App   │
└──────┬───────┘
       │ Authenticate + Authorize
       ↓
┌──────────────┐
│ Policy Engine│ ← Context (device, location, time)
└──────┬───────┘
       │ Allow/Deny
       ↓
┌──────────────┐
│   Resource   │ (Encrypted, segmented)
└──────────────┘
```

**Benefit**: Every access verified, no implicit trust

## Key Components

### 1. Identity and Access Management (IAM)
- **MFA (Multi-Factor Authentication)**: Always require
- **SSO (Single Sign-On)**: Centralized authentication
- **Identity Provider**: Source of truth for users

### 2. Device Security
- **Device Inventory**: Know all devices
- **Posture Checks**: Verify device health
- **Managed Devices**: Enforce compliance
- **Unmanaged Devices**: Restrict access

### 3. Network Segmentation
- **Microsegmentation**: Isolate workloads
- **VLANs**: Logical separation
- **Software-Defined Perimeter**: Dynamic boundaries

### 4. Application Security
- **API Gateways**: Control access to services
- **Service Mesh**: Service-to-service authentication
- **Encryption**: TLS/mTLS everywhere

### 5. Data Security
- **Classification**: Label data sensitivity
- **Encryption**: At rest and in transit
- **DLP (Data Loss Prevention)**: Monitor/block exfiltration

### 6. Policy Engine
- **Context-Aware**: Identity + device + location + time
- **Adaptive**: Adjust based on risk
- **Automated**: Real-time decisions

### 7. Monitoring and Analytics
- **Logging**: All access attempts
- **SIEM**: Security Information Event Management
- **Anomaly Detection**: Identify threats
- **Incident Response**: Rapid containment

## Zero Trust Architecture

```
┌─────────────────────────────────────────────────────────┐
│                 Control Plane                            │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐ │
│  │ Identity │  │  Device  │  │  Policy  │  │ Threat │ │
│  │   Store  │  │ Registry │  │  Engine  │  │ Intel  │ │
│  └──────────┘  └──────────┘  └──────────┘  └────────┘ │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│                 Data Plane                               │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐ │
│  │  Policy  │  │  Policy  │  │  Policy  │  │ Policy │ │
│  │Enforcement│ │Enforcement│ │Enforcement│ │Enforce │ │
│  │  Point   │  │  Point   │  │  Point   │  │  Point │ │
│  │  (PEP)   │  │  (PEP)   │  │  (PEP)   │  │  (PEP) │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬───┘ │
│       │             │              │              │     │
│  ┌────▼─────┐  ┌───▼──────┐  ┌───▼──────┐  ┌───▼────┐│
│  │   App    │  │   API    │  │    DB    │  │  File  ││
│  └──────────┘  └──────────┘  └──────────┘  └────────┘│
└─────────────────────────────────────────────────────────┘
```

## Implementation Example

### Zero Trust Policy (OPA/Rego)

```rego
package authz

import future.keywords.if
import future.keywords.in

# Default deny
default allow = false

# Allow if all conditions met
allow if {
    # 1. User authenticated
    valid_user

    # 2. Device is compliant
    compliant_device

    # 3. Appropriate access level
    sufficient_permission

    # 4. Not anomalous behavior
    not suspicious_activity

    # 5. Within allowed time
    allowed_time
}

# User must be authenticated with MFA
valid_user if {
    input.user.authenticated == true
    input.user.mfa_verified == true
    input.user.session_valid == true
}

# Device must meet security posture
compliant_device if {
    input.device.managed == true
    input.device.os_updated == true
    input.device.antivirus_active == true
    input.device.encrypted == true
}

# User must have required permission
sufficient_permission if {
    required_role := data.permissions[input.resource][input.action]
    input.user.role == required_role
}

# Check for anomalies
suspicious_activity if {
    # Unusual location
    input.location.country != input.user.usual_country
}

suspicious_activity if {
    # Unusual time
    hour := time.clock(time.now_ns())[0]
    hour < 6
    hour > 22
}

# Business hours check
allowed_time if {
    hour := time.clock(time.now_ns())[0]
    hour >= 9
    hour <= 17
}

# Allow after-hours for specific roles
allowed_time if {
    input.user.role in ["admin", "oncall"]
}
```

### Request Flow

```json
{
  "user": {
    "id": "alice@example.com",
    "authenticated": true,
    "mfa_verified": true,
    "session_valid": true,
    "role": "engineer",
    "usual_country": "US"
  },
  "device": {
    "id": "device-123",
    "managed": true,
    "os_updated": true,
    "antivirus_active": true,
    "encrypted": true
  },
  "location": {
    "ip": "203.0.113.1",
    "country": "US"
  },
  "resource": "database:prod",
  "action": "read",
  "timestamp": "2025-11-16T14:30:00Z"
}
```

### Zero Trust with Service Mesh (Istio)

```yaml
# Authentication policy
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT  # Require mutual TLS

---
# Authorization policy
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: db-access
  namespace: production
spec:
  selector:
    matchLabels:
      app: database
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/production/sa/api-service"]
    to:
    - operation:
        methods: ["GET", "POST"]
    when:
    - key: request.auth.claims[verified]
      values: ["true"]
```

## Use Cases

### 1. Remote Workforce
**Challenge**: Employees work from anywhere
**Solution**:
- VPN-less access via Zero Trust Network Access (ZTNA)
- Device posture checks before granting access
- Continuous authentication

### 2. Cloud Migration
**Challenge**: Resources in multiple clouds
**Solution**:
- Consistent policy across environments
- Identity-based access (not network-based)
- Encryption in transit and at rest

### 3. Third-Party Access
**Challenge**: Vendors need limited access
**Solution**:
- Just-in-time access provisioning
- Granular permissions
- Time-bound access

### 4. Mergers & Acquisitions
**Challenge**: Integrate new organizations
**Solution**:
- No network trust required
- Identity federation
- Gradual integration

## Benefits

✅ **Improved Security**: Reduced attack surface
✅ **Compliance**: Meet regulatory requirements
✅ **Flexibility**: Support remote work
✅ **Visibility**: Better audit trails
✅ **Scalability**: Cloud-native approach
✅ **Reduced Complexity**: Eliminate VPN bottlenecks

## Challenges

❌ **Cultural Shift**: Requires organizational change
❌ **Initial Cost**: Significant upfront investment
❌ **Complexity**: Multiple components to integrate
❌ **Performance**: Potential latency from checks
❌ **Legacy Systems**: Hard to retrofit old applications

## Zero Trust Maturity Model

### Level 1: Traditional (Ad-Hoc)
- Perimeter-based security
- Static credentials
- No segmentation

### Level 2: Initial (Beginner)
- Basic MFA implemented
- Some network segmentation
- Logging enabled

### Level 3: Advanced (Intermediate)
- Comprehensive MFA
- Microsegmentation
- Policy-based access
- Device compliance checks

### Level 4: Optimal (Advanced)
- Continuous authentication
- Automated policy enforcement
- AI-driven threat detection
- Full encryption
- Microsegmentation everywhere

### Level 5: Automated (Expert)
- Self-healing systems
- Predictive threat modeling
- Zero standing privileges
- Fully automated response

## Technologies and Tools

### Identity & Access
- **Okta**: Identity provider
- **Azure AD**: Microsoft identity platform
- **Auth0**: Authentication platform
- **Keycloak**: Open-source IAM

### Network Security
- **Cloudflare Access**: Zero Trust network access
- **Zscaler**: Cloud security platform
- **Palo Alto Prisma Access**: SASE solution

### Policy Engines
- **OPA (Open Policy Agent)**: Policy-based control
- **Styra**: Commercial OPA offering
- **HashiCorp Sentinel**: Policy as code

### Service Mesh
- **Istio**: Service-to-service security
- **Linkerd**: Lightweight service mesh
- **Consul**: Service networking

### Device Management
- **Jamf**: Apple device management
- **Microsoft Intune**: Endpoint management
- **Google Workspace**: Device management

### Monitoring
- **Splunk**: SIEM platform
- **Datadog**: Monitoring and security
- **Elastic Security**: Threat detection

## Implementation Roadmap

### Phase 1: Foundation (Months 1-3)
1. Inventory all users, devices, applications
2. Implement MFA everywhere
3. Deploy centralized logging
4. Classify data sensitivity

### Phase 2: Identity-Centric (Months 4-6)
1. Deploy identity provider (IDP)
2. Implement SSO
3. Define role-based policies
4. Device enrollment and compliance

### Phase 3: Network Segmentation (Months 7-9)
1. Implement microsegmentation
2. Deploy service mesh for apps
3. Enforce encryption (TLS/mTLS)
4. Remove implicit trust zones

### Phase 4: Advanced Policies (Months 10-12)
1. Context-aware policies
2. Risk-based adaptive access
3. Automated threat response
4. Continuous monitoring

### Phase 5: Optimization (Ongoing)
1. Refine policies based on analytics
2. User behavior analytics (UBA)
3. Automated remediation
4. Zero standing privileges

## Best Practices

1. **Start with Identity**: Strong IAM is foundation
2. **Segment Everything**: No flat networks
3. **Encrypt All Traffic**: TLS 1.3+ everywhere
4. **Log Everything**: Comprehensive audit trail
5. **Automate Policy**: Manual processes don't scale
6. **Least Privilege**: Default deny, explicit allow
7. **Verify Devices**: Posture checks mandatory
8. **Monitor Continuously**: Real-time threat detection
9. **Educate Users**: Security awareness training
10. **Measure Progress**: Track maturity over time

## Standards and Frameworks

- **NIST SP 800-207**: Zero Trust Architecture
- **CISA Zero Trust Maturity Model**: US government framework
- **Forrester Zero Trust**: Original Zero Trust model
- **Google BeyondCorp**: Google's Zero Trust implementation
- **NCSC Zero Trust**: UK guidance

## Further Reading

- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [CISA Zero Trust Maturity Model](https://www.cisa.gov/zero-trust-maturity-model)
- [Google BeyondCorp Papers](https://cloud.google.com/beyondcorp)
- [Microsoft Zero Trust](https://www.microsoft.com/en-us/security/business/zero-trust)

## Next Steps

- Understand [ABAC](./abac.md) for policy-based control
- Learn [OPA](../../frameworks/opa/) for policy enforcement
- Review [Policy Making](../policy-standards/policy-making.md)
- Explore [OAuth 2.0](../tokens-sessions/oauth2.md) for identity
