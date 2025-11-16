# OSO

## Overview

**OSO** is an authorization library with a declarative policy language called Polar. It provides application-level authorization with deep integration into your application's data model, including support for data filtering and type-safe policies.

**Website**: [osohq.com](https://www.osohq.com/)
**GitHub**: [github.com/osohq/oso](https://github.com/osohq/oso)
**License**: Apache 2.0
**Company**: Oso Security

## Why OSO?

- **Developer-Friendly**: Natural, readable policy syntax (Polar)
- **Application-Level**: Deep integration with app logic
- **Data Filtering**: Automatically generate SQL/ORM filters
- **Type-Safe**: Validates policies against your data model
- **Multi-Language**: Python, Ruby, Java, Node.js, Go, Rust
- **Framework Integration**: Django, Rails, Spring Boot, Express
- **Testing**: Built-in policy testing tools

## Use Cases

- **Application Authorization**: Who can do what in your app
- **Multi-Tenant SaaS**: Tenant-specific permissions
- **Data Filtering**: Show only authorized data
- **API Authorization**: Protect REST/GraphQL APIs
- **Role-Based Access**: Traditional RBAC
- **Resource Ownership**: Owner-based permissions

## Quick Start

### Installation

#### Python
```bash
pip install oso
```

#### Node.js
```bash
npm install oso
```

#### Ruby
```bash
gem install oso-oso
```

#### Java
```xml
<dependency>
    <groupId>com.osohq</groupId>
    <artifactId>oso</artifactId>
    <version>0.26.0</version>
</dependency>
```

#### Go
```bash
go get github.com/osohq/go-oso
```

### Basic Example (Python)

**policy.polar**:
```polar
# Allow admins to do anything
allow(actor: User, _action, _resource) if
    actor.role = "admin";

# Allow users to read their own posts
allow(actor: User, "read", post: Post) if
    post.created_by = actor;

# Allow users to edit their own posts
allow(actor: User, "edit", post: Post) if
    post.created_by = actor;
```

**app.py**:
```python
from oso import Oso
from dataclasses import dataclass

@dataclass
class User:
    id: int
    role: str

@dataclass
class Post:
    id: int
    title: str
    created_by: User

# Initialize Oso
oso = Oso()

# Register classes
oso.register_class(User)
oso.register_class(Post)

# Load policy
oso.load_file("policy.polar")

# Create instances
alice = User(id=1, role="user")
bob = User(id=2, role="admin")
post = Post(id=1, title="Hello", created_by=alice)

# Check permissions
print(oso.is_allowed(alice, "read", post))  # True (owner)
print(oso.is_allowed(alice, "edit", post))  # True (owner)
print(oso.is_allowed(bob, "read", post))    # True (admin)
print(oso.is_allowed(User(id=3, role="user"), "read", post))  # False
```

## Polar Language

### Basic Syntax

#### Rules

```polar
# Simple rule
can_read(user, post) if
    post.created_by = user;

# Rule with OR (multiple rules with same head)
can_edit(user, post) if post.created_by = user;
can_edit(user, post) if user.role = "admin";

# Rule with AND (multiple conditions)
can_delete(user, post) if
    post.created_by = user and
    user.is_active = true;
```

#### Variables

```polar
# Unbound variable
allow(user, "read", post) if
    owner = post.created_by and
    owner.department = user.department;

# Pattern matching
allow(user, "read", Post{id: post_id}) if
    has_access(user, post_id);
```

#### Types

```polar
# Type constraints
allow(actor: User, "edit", resource: Post) if
    resource.author = actor;

# Type checking is automatic when registered
```

### Built-in Operations

```polar
# Comparison
x = y    # Equality
x != y   # Inequality
x < y, x > y, x <= y, x >= y  # Comparisons

# Logical
condition1 and condition2
condition1 or condition2
not condition

# Collections
item in list
key in dict

# String matching
"hello" matches "h*"
```

### Specializers

Provide implementations for specific types:

```polar
# Specializer for User type
has_permission(user: User, permission: String) if
    permission in user.permissions;

# Specializer for Group type
has_permission(group: Group, permission: String) if
    member in group.members and
    has_permission(member, permission);
```

## Data Filtering

OSO can generate database queries to fetch only authorized data.

### Python (Django)

```python
from oso import Oso
from django_oso.auth import authorize_model

# Policy
"""
allow(user: User, "read", post: Post) if
    post.is_public = true;

allow(user: User, "read", post: Post) if
    post.created_by = user;
"""

# In your view
@login_required
def posts_view(request):
    # OSO automatically filters
    posts = authorize_model(
        request.user,
        "read",
        Post,
        oso_instance=oso
    )
    # Returns only posts user can read
    return render(request, "posts.html", {"posts": posts})
```

Generated SQL (approximately):
```sql
SELECT * FROM posts
WHERE is_public = true
   OR created_by_id = <current_user_id>;
```

### Python (SQLAlchemy)

```python
from sqlalchemy_oso import authorized_sessionmaker
from oso import Oso

# Create authorized session
AuthorizedSession = authorized_sessionmaker(
    bind=engine,
    get_oso=lambda: oso,
    get_user=lambda: current_user,
    get_action=lambda: "read"
)

session = AuthorizedSession()

# This query is automatically filtered
posts = session.query(Post).all()
# Only returns posts user can read
```

## Framework Integration

### Django

**Install**:
```bash
pip install django-oso
```

**settings.py**:
```python
INSTALLED_APPS = [
    ...
    'django_oso',
]

MIDDLEWARE = [
    ...
    'django_oso.middleware.OsoMiddleware',
]
```

**policy.polar**:
```polar
allow(user: User, "read", post: Post) if
    post.is_public = true or
    post.author = user;

allow(user: User, "edit", post: Post) if
    post.author = user;

allow(user: User, "delete", post: Post) if
    post.author = user and
    user.is_staff = true;
```

**views.py**:
```python
from django_oso.decorators import authorize

@authorize(action="read")
def post_detail(request, post_id):
    post = Post.objects.get(id=post_id)
    return render(request, "post.html", {"post": post})

# Or use authorize_model for filtering
def post_list(request):
    posts = authorize_model(request.user, "read", Post)
    return render(request, "posts.html", {"posts": posts})
```

### Flask

```python
from flask import Flask, g
from oso import Oso
from flask_oso import FlaskOso

app = Flask(__name__)
oso = Oso()
flask_oso = FlaskOso(app, oso)

# Load policy
oso.load_file("policy.polar")

# Set current user
@app.before_request
def set_user():
    g.current_user = get_current_user()

# Protected route
@app.route("/posts/<int:post_id>")
@flask_oso.authorize(resource=lambda post_id: Post.get(post_id))
def post_detail(post_id):
    post = Post.get(post_id)
    return render_template("post.html", post=post)
```

### Ruby on Rails

**Gemfile**:
```ruby
gem 'oso-oso'
gem 'oso-rails'
```

**policy.polar**:
```polar
allow(user: User, "read", post: Post) if
    post.published = true or
    post.author = user;
```

**Controller**:
```ruby
class PostsController < ApplicationController
  def show
    @post = Post.find(params[:id])
    authorize(@post, action: :read)
  end

  def index
    @posts = authorize(Post, action: :read)
  end
end
```

### Express (Node.js)

```javascript
const { Oso } = require('oso');
const express = require('express');

const app = express();
const oso = new Oso();

// Register classes
class User {
    constructor(id, role) {
        this.id = id;
        this.role = role;
    }
}

class Post {
    constructor(id, authorId) {
        this.id = id;
        this.authorId = authorId;
    }
}

oso.registerClass(User);
oso.registerClass(Post);

// Load policy
await oso.loadFile('policy.polar');

// Middleware
async function authorize(action) {
    return async (req, res, next) => {
        const resource = await getResource(req);
        const allowed = await oso.isAllowed(req.user, action, resource);

        if (!allowed) {
            return res.status(403).send('Forbidden');
        }

        next();
    };
}

// Protected route
app.get('/posts/:id', authorize('read'), async (req, res) => {
    const post = await Post.findById(req.params.id);
    res.json(post);
});

app.listen(3000);
```

## Advanced Patterns

### Role Hierarchies

```polar
# Define role hierarchy
role_hierarchy("admin", "editor");
role_hierarchy("editor", "viewer");

# Transitive closure
has_role(user, role) if user.role = role;
has_role(user, role) if
    role_hierarchy(user.role, intermediate) and
    has_role_internal(intermediate, role);

# Use in authorization
allow(user, action, resource) if
    has_role(user, required_role) and
    role_permissions(required_role, action);
```

### Group Membership

```polar
# User belongs to group
in_group(user: User, group: Group) if
    user in group.members;

# Recursive groups
in_group(user: User, group: Group) if
    child_group in group.sub_groups and
    in_group(user, child_group);

# Use in permissions
allow(user, "read", document) if
    in_group(user, document.allowed_group);
```

### Multi-Tenancy

```polar
# Tenant isolation
allow(user: User, action, resource) if
    user.tenant_id = resource.tenant_id and
    has_permission(user, action, resource);

# Cross-tenant admin
allow(user: User, action, resource) if
    user.role = "super_admin";
```

### Time-Based Access

```polar
# During business hours
allow(user, "access_sensitive", resource) if
    current_hour() >= 9 and
    current_hour() < 17 and
    user.role = "analyst";

# Temporary access
allow(user, action, resource) if
    grant = temporary_grant(user, resource) and
    grant.expires_at > now() and
    grant.action = action;
```

## Testing Policies

```python
import pytest
from oso import Oso

@pytest.fixture
def oso():
    oso = Oso()
    oso.register_class(User)
    oso.register_class(Post)
    oso.load_file("policy.polar")
    return oso

def test_owner_can_read(oso):
    alice = User(id=1, role="user")
    post = Post(id=1, created_by=alice)

    assert oso.is_allowed(alice, "read", post)

def test_non_owner_cannot_read(oso):
    alice = User(id=1, role="user")
    bob = User(id=2, role="user")
    post = Post(id=1, created_by=alice)

    assert not oso.is_allowed(bob, "read", post)

def test_admin_can_read_all(oso):
    admin = User(id=3, role="admin")
    post = Post(id=1, created_by=User(id=1, role="user"))

    assert oso.is_allowed(admin, "read", post)
```

## Debugging

```python
# Enable detailed logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Query for debugging
oso.query_rule("allow", alice, "read", post)
# Shows which rules matched

# Explain authorization decision
result = oso.query_rule("allow", alice, "read", post)
for binding in result:
    print(f"Allowed via: {binding}")
```

## Performance

### Caching

```python
# Cache authorization decisions
from functools import lru_cache

@lru_cache(maxsize=1000)
def is_allowed_cached(user_id, action, resource_id):
    user = User.get(user_id)
    resource = Resource.get(resource_id)
    return oso.is_allowed(user, action, resource)
```

### Partial Evaluation

OSO can partially evaluate policies for better performance:

```python
# Compile policy for specific user
compiled = oso.partial_eval(alice, "read")
# Now check specific resources faster
compiled.is_allowed(post1)
compiled.is_allowed(post2)
```

## Best Practices

1. **Keep Policies Simple**: Break complex rules into smaller pieces
2. **Use Types**: Register all classes for type safety
3. **Test Thoroughly**: Write tests for all authorization scenarios
4. **Data Filtering**: Use authorized queries instead of checking individually
5. **Cache Results**: Cache authorization decisions when appropriate
6. **Version Policies**: Track policy changes in version control
7. **Document Rules**: Add comments to complex polar rules
8. **Monitor Performance**: Track authorization check latency
9. **Principle of Least Privilege**: Default deny, explicit allow
10. **Regular Audits**: Review policies periodically

## Comparison

| Feature | OSO | OPA | Casbin |
|---------|-----|-----|--------|
| **Language** | Polar | Rego | Model files |
| **Data Filtering** | ✅ | ⚠️ | ❌ |
| **Type Safety** | ✅ | ⚠️ | ❌ |
| **App Integration** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Performance** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Cloud-Native** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |

## Further Resources

- **Documentation**: [docs.osohq.com](https://docs.osohq.com/)
- **Guides**: [osohq.com/guides](https://www.osohq.com/guides)
- **Academy**: [osohq.com/academy](https://www.osohq.com/academy)
- **Examples**: [github.com/osohq/oso/examples](https://github.com/osohq/oso/tree/main/docs/examples)

## Community

- **Slack**: [osohq.com/slack](https://www.osohq.com/slack)
- **GitHub Discussions**: [github.com/osohq/oso/discussions](https://github.com/osohq/oso/discussions)
- **Stack Overflow**: Tag `oso`

## Next Steps

- Review [ABAC Concepts](../../fundamentals/concepts/abac.md)
- Understand [Policy Making](../../fundamentals/policy-standards/policy-making.md)
- Compare with [OPA](../opa/README.md) and [Casbin](../casbin/README.md)
- Check [Comparative Analysis](../../COMPARISON.md)
