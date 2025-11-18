# CASL React Example

A complete full-stack application demonstrating CASL (isomorphic authorization) with React and Express.

## Overview

This example demonstrates:
- Client-side authorization with CASL in React
- Server-side authorization with CASL in Express
- JWT authentication
- Ability-based permissions
- Field-level permissions
- Conditional rules
- React context for abilities

## Architecture

```
┌─────────────────┐
│  React Frontend │
│   (port 3000)   │
│   - CASL Client │
│   - React Context│
└────────┬────────┘
         │ HTTP + JWT
         ▼
┌─────────────────┐
│ Express Backend │
│   (port 3001)   │
│   - CASL Server │
│   - JWT Auth    │
└─────────────────┘
```

## Features

- **Authentication**: JWT-based login system
- **Authorization**: Role and ownership-based permissions
- **Dynamic UI**: Hide/show elements based on permissions
- **API Protection**: Server-side permission checks
- **Field-level**: Control access to specific fields
- **Reactive**: Real-time permission updates

## Files Structure

```
casl-react/
├── backend/
│   ├── server.js          # Express server
│   ├── abilities.js       # CASL ability definitions
│   ├── middleware.js      # Auth middleware
│   ├── routes/
│   │   ├── auth.js        # Authentication routes
│   │   ├── posts.js       # Post CRUD operations
│   │   └── users.js       # User management
│   └── package.json
├── frontend/
│   ├── src/
│   │   ├── App.js         # Main app component
│   │   ├── abilities.js   # CASL ability definitions
│   │   ├── context/
│   │   │   ├── AuthContext.js   # Auth state
│   │   │   └── AbilityContext.js # CASL context
│   │   ├── components/
│   │   │   ├── Login.js
│   │   │   ├── PostList.js
│   │   │   ├── PostForm.js
│   │   │   └── Can.js     # Permission wrapper
│   │   └── api.js         # API client
│   └── package.json
├── docker-compose.yml
└── README.md
```

## Quick Start

### Prerequisites

- Node.js 18+
- npm or yarn
- Docker (optional)

### Option 1: Run with Docker

```bash
# Build and start both frontend and backend
docker-compose up --build

# Frontend: http://localhost:3000
# Backend API: http://localhost:3001
```

### Option 2: Run Locally

```bash
# Terminal 1: Backend
cd backend
npm install
npm start

# Terminal 2: Frontend
cd frontend
npm install
npm start
```

## Default Users

| Username | Password | Role    | Permissions                          |
|----------|----------|---------|--------------------------------------|
| admin    | admin123 | admin   | Full access to everything            |
| alice    | alice123 | editor  | Create/edit own posts, read all      |
| bob      | bob123   | viewer  | Read all posts                       |

## Using the Application

### 1. Login

Visit `http://localhost:3000` and login with any user above.

### 2. View Posts

All users can view posts. The UI will show different actions based on permissions.

### 3. Create Post

Editors and admins can create posts. Click "Create Post" button.

### 4. Edit Post

Users can edit their own posts. Admins can edit any post.

### 5. Delete Post

Only admins can delete posts.

## CASL Abilities

### User Role (Viewer)

```javascript
{
  can('read', 'Post'),
  cannot('create', 'Post'),
  cannot('update', 'Post'),
  cannot('delete', 'Post')
}
```

### Editor Role

```javascript
{
  can('read', 'Post'),
  can('create', 'Post'),
  can('update', 'Post', { authorId: userId }),  // Own posts only
  cannot('delete', 'Post')
}
```

### Admin Role

```javascript
{
  can('manage', 'all')  // Full access
}
```

## Code Examples

### Define Abilities (backend/abilities.js)

```javascript
import { AbilityBuilder, Ability } from '@casl/ability';

export function defineAbilitiesFor(user) {
  const { can, cannot, build } = new AbilityBuilder(Ability);

  if (user.role === 'admin') {
    can('manage', 'all');
  } else if (user.role === 'editor') {
    can('read', 'Post');
    can('create', 'Post');
    can('update', 'Post', { authorId: user.id });
  } else {
    can('read', 'Post');
  }

  return build();
}
```

### Use in React Component

```javascript
import { Can } from './components/Can';

function PostItem({ post }) {
  return (
    <div>
      <h3>{post.title}</h3>
      <p>{post.content}</p>

      <Can I="update" this={post}>
        <button>Edit</button>
      </Can>

      <Can I="delete" this={post}>
        <button>Delete</button>
      </Can>
    </div>
  );
}
```

### Protect API Routes

```javascript
import { defineAbilitiesFor } from './abilities';

app.delete('/api/posts/:id', requireAuth, async (req, res) => {
  const ability = defineAbilitiesFor(req.user);
  const post = await Post.findById(req.params.id);

  if (ability.cannot('delete', post)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  await post.delete();
  res.json({ message: 'Deleted' });
});
```

## API Endpoints

### Authentication

```bash
# Login
POST /api/auth/login
{
  "username": "alice",
  "password": "alice123"
}

# Get current user
GET /api/auth/me
Authorization: Bearer <token>
```

### Posts

```bash
# List posts
GET /api/posts

# Create post
POST /api/posts
Authorization: Bearer <token>
{
  "title": "My Post",
  "content": "Hello World"
}

# Update post
PUT /api/posts/:id
Authorization: Bearer <token>
{
  "title": "Updated Title"
}

# Delete post
DELETE /api/posts/:id
Authorization: Bearer <token>
```

## Customization

### Add New Permission

1. **Define in abilities.js**:
```javascript
can('publish', 'Post', { status: 'draft' })
```

2. **Use in React**:
```javascript
<Can I="publish" this={post}>
  <button>Publish</button>
</Can>
```

3. **Check on server**:
```javascript
if (ability.can('publish', post)) {
  // Allow publish
}
```

### Field-Level Permissions

```javascript
// Only admin can see email field
can('read', 'User', ['name', 'role'])
can('read', 'User', 'email', { role: 'admin' })

// In React
<Can I="read" a="User" field="email">
  <div>Email: {user.email}</div>
</Can>
```

### Conditional Rules

```javascript
// Only during business hours
can('create', 'Post', {
  condition: () => {
    const hour = new Date().getHours();
    return hour >= 9 && hour < 17;
  }
})
```

## Testing

### Run Backend Tests

```bash
cd backend
npm test
```

### Run Frontend Tests

```bash
cd frontend
npm test
```

### Manual Testing

```bash
# Test as different users
make test-admin
make test-editor
make test-viewer
```

## Development

### Hot Reload

Both frontend and backend support hot reloading:

```bash
# Backend (automatically restarts on changes)
cd backend
npm run dev

# Frontend (React hot reload)
cd frontend
npm start
```

### Debug Mode

Enable debug logging:

```bash
# Backend
DEBUG=casl:* npm start

# Frontend
REACT_APP_DEBUG=true npm start
```

## Deployment

### Production Build

```bash
# Build frontend
cd frontend
npm run build

# Backend serves static files
cd ../backend
npm start
```

### Environment Variables

Create `.env` files:

**backend/.env**:
```
PORT=3001
JWT_SECRET=your-secret-key
NODE_ENV=production
```

**frontend/.env**:
```
REACT_APP_API_URL=https://api.example.com
```

## Common Patterns

### Check Multiple Abilities

```javascript
if (ability.can('update', post) || ability.can('delete', post)) {
  // Show actions menu
}
```

### Inverted Checks

```javascript
<Can not I="create" a="Post">
  <div>Upgrade to create posts</div>
</Can>
```

### Subject Type Matching

```javascript
// Different subjects
can('read', 'Post')
can('update', 'Comment')
cannot('delete', 'User')
```

## Troubleshooting

**401 Unauthorized**
- Token expired or invalid
- Check Authorization header format: `Bearer <token>`

**403 Forbidden**
- User lacks permission
- Check ability definitions
- Verify subject conditions

**Abilities not updating**
- Ensure AbilityContext provider wraps components
- Call `updateAbility` when user changes

**Field-level not working**
- Use `<Can field="fieldName">` prop
- Define field permissions in abilities

## Next Steps

- Add more complex permissions
- Implement role management UI
- Add audit logging
- Integrate with real database
- Add tests for all abilities
- Implement refresh tokens

## Resources

- [CASL Documentation](https://casl.js.org/)
- [React Integration](https://casl.js.org/v6/en/package/casl-react)
- [Examples](https://github.com/stalniy/casl-examples)

## License

MIT
