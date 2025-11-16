# Authorization Examples

## Overview

This directory contains practical implementation examples for various authorization frameworks and patterns. Each example is self-contained and demonstrates real-world usage.

## Available Examples

### 1. OPA Simple (opa-simple/)
**Framework**: Open Policy Agent
**Language**: Rego + Go/Python
**Difficulty**: Beginner

A simple RBAC example using OPA with:
- Policy definitions in Rego
- Sample data
- HTTP API integration
- Docker setup

**What you'll learn**:
- Writing Rego policies
- Running OPA server
- Making authorization decisions via API

### 2. Casbin RBAC (casbin-rbac/)
**Framework**: Casbin
**Language**: Go/Python/Node.js
**Difficulty**: Beginner

Basic RBAC implementation with:
- Model configuration
- Policy CSV file
- HTTP middleware
- Dynamic policy updates

**What you'll learn**:
- Casbin model syntax
- Policy management
- Middleware integration

### 3. CASL React (casl-react/)
**Framework**: CASL
**Language**: TypeScript/React
**Difficulty**: Intermediate

Full-stack authorization with:
- React frontend with CASL
- Node.js backend
- Isomorphic permission logic
- Database filtering

**What you'll learn**:
- Frontend authorization
- Sharing logic between frontend/backend
- Type-safe permissions

### 4. Multi-Tenant (multi-tenant/)
**Framework**: Multiple (comparison)
**Language**: Go
**Difficulty**: Advanced

Multi-tenant SaaS authorization with:
- Tenant isolation
- Hierarchical permissions
- Different framework implementations
- Performance comparison

**What you'll learn**:
- Multi-tenancy patterns
- Framework trade-offs
- Scalability considerations

## How to Use These Examples

### Prerequisites
- Docker and Docker Compose
- Git
- Basic programming knowledge
- Familiarity with concepts from [fundamentals](../fundamentals/)

### Quick Start

1. **Clone and Navigate**
   ```bash
   cd examples/opa-simple
   ```

2. **Follow Example README**
   Each example has its own README with:
   - Setup instructions
   - Running the example
   - Testing scenarios
   - Extending the example

3. **Experiment**
   - Modify policies
   - Add new roles
   - Test edge cases
   - Break things and fix them!

## Example Structure

Each example typically contains:

```
example-name/
├── README.md           # Detailed instructions
├── docker-compose.yml  # Docker setup
├── policies/           # Authorization policies
├── src/                # Source code
├── tests/              # Test cases
└── .env.example        # Environment variables
```

## Learning Path Integration

These examples complement the [Learning Path](../LEARNING_PATH.md):

- **Beginners**: Start with `opa-simple` or `casbin-rbac`
- **Intermediate**: Try `casl-react` for full-stack
- **Advanced**: Tackle `multi-tenant` for complex scenarios

## Running Examples

### Using Docker (Recommended)

```bash
cd examples/opa-simple
docker-compose up
```

### Local Development

```bash
cd examples/casl-react
npm install
npm run dev
```

## Example Scenarios

### Scenario 1: Blog Platform
**Examples**: casbin-rbac, casl-react

Implement authorization for a blog:
- Admins can do everything
- Authors can edit their own posts
- Readers can only view published posts

### Scenario 2: File Sharing
**Examples**: opa-simple

Build file permission system:
- Owners have full control
- Shared users have view access
- Public files accessible to all

### Scenario 3: API Gateway
**Examples**: opa-simple, casbin-rbac

Protect REST APIs:
- Role-based endpoint access
- Rate limiting per role
- Request validation

### Scenario 4: Multi-Tenant SaaS
**Examples**: multi-tenant

Enterprise application:
- Tenant isolation
- Per-tenant admin roles
- Cross-tenant super admin

## Testing Examples

Each example includes tests:

```bash
# Unit tests
npm test

# Integration tests
npm run test:integration

# E2E tests
npm run test:e2e
```

## Extending Examples

### Add New Roles
1. Update policy files
2. Add test cases
3. Update documentation

### Add New Resources
1. Define resource structure
2. Create authorization rules
3. Implement in code

### Add New Features
1. Authentication integration
2. Audit logging
3. Performance monitoring

## Common Patterns Demonstrated

### Pattern 1: Middleware Authorization
**Examples**: casbin-rbac, opa-simple

```javascript
function authorize(req, res, next) {
    const allowed = checkPermission(req.user, req.path, req.method);
    if (allowed) next();
    else res.status(403).send('Forbidden');
}
```

### Pattern 2: Component-Level Authorization
**Examples**: casl-react

```jsx
<Can I="edit" this={post}>
    <EditButton />
</Can>
```

### Pattern 3: Data Filtering
**Examples**: casl-react, multi-tenant

```javascript
const posts = await Post.find(accessibleBy(ability, 'read'));
```

### Pattern 4: Hierarchical Permissions
**Examples**: multi-tenant

```
Organization Admin
  ├── Team Admin
  │   └── Team Member
  └── Viewer
```

## Troubleshooting

### Common Issues

**Issue**: "Permission denied" when running examples
**Solution**: Ensure Docker has necessary permissions

**Issue**: "Port already in use"
**Solution**: Change port in docker-compose.yml

**Issue**: "Cannot connect to authorization service"
**Solution**: Wait for service to be fully ready (check health endpoint)

### Getting Help

1. Check example README
2. Review [framework documentation](../frameworks/)
3. Check [GLOSSARY](../GLOSSARY.md) for terms
4. Ask in framework communities

## Best Practices Demonstrated

1. **Default Deny**: All examples start with deny-by-default
2. **Least Privilege**: Grant minimum necessary permissions
3. **Testing**: Comprehensive test coverage
4. **Documentation**: Clear README and code comments
5. **Security**: Follow security best practices
6. **Logging**: Audit trail for authorization decisions

## Performance Benchmarks

Some examples include benchmarks:

```bash
cd examples/multi-tenant
npm run benchmark
```

Typical results:
- **OPA**: < 1ms per check
- **Casbin**: < 1ms per check
- **CASL**: < 0.5ms per check

## Contributing Examples

Want to add an example? Great!

### Guidelines
1. Follow existing structure
2. Include comprehensive README
3. Add tests
4. Document clearly
5. Use Docker when possible

### Submission Process
1. Fork repository
2. Create example in `examples/your-example/`
3. Test thoroughly
4. Submit pull request

## Related Resources

- [Framework Documentation](../frameworks/)
- [Fundamentals](../fundamentals/)
- [Comparison](../COMPARISON.md)
- [Learning Path](../LEARNING_PATH.md)

## Roadmap

### Planned Examples
- [ ] Keycloak SSO integration
- [ ] SpiceDB Google Drive clone
- [ ] OSO with Django
- [ ] Microservices authorization
- [ ] GraphQL authorization

### Community Contributions Welcome!

---

**Note**: These examples are for learning purposes. For production use, review security considerations and adapt to your specific requirements.

**Happy coding!** 🚀
