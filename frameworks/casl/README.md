# CASL (Code Access Security Library)

## Overview

**CASL** is an isomorphic authorization library for JavaScript and TypeScript that allows you to manage user permissions in both frontend and backend applications. It provides a unified API for defining and checking abilities across your entire JavaScript stack.

**Website**: [casl.js.org](https://casl.js.org/)
**GitHub**: [github.com/stalniy/casl](https://github.com/stalniy/casl)
**License**: MIT

## Why CASL?

- **Isomorphic**: Same logic for frontend and backend
- **Framework Agnostic**: Works with React, Vue, Angular, Node.js
- **TypeScript**: Full TypeScript support
- **Lightweight**: ~10KB gzipped
- **Flexible**: Supports RBAC, ABAC, and more
- **Declarative**: Intuitive ability definitions
- **Reactive**: Updates UI automatically when permissions change
- **Database Integration**: Generate database queries from abilities

## Use Cases

- **React/Vue/Angular Apps**: Client-side authorization
- **Node.js APIs**: Backend authorization
- **Full-Stack Apps**: Shared permission logic
- **SPA + Backend**: Consistent authorization
- **Admin Panels**: Role-based UI
- **Multi-Tenant Apps**: Tenant-specific permissions

## Quick Start

### Installation

```bash
# Core library
npm install @casl/ability

# React integration
npm install @casl/react

# Vue integration
npm install @casl/vue

# Angular integration
npm install @casl/angular
```

### Basic Example

```javascript
import { AbilityBuilder, Ability } from '@casl/ability';

// Define abilities
function defineAbilitiesFor(user) {
    const { can, cannot, build } = new AbilityBuilder(Ability);

    if (user.role === 'admin') {
        // Admin can do everything
        can('manage', 'all');
    } else {
        // Regular users
        can('read', 'Article');
        can('update', 'Article', { authorId: user.id });
        can('create', 'Comment');
        cannot('delete', 'Comment', { published: true });
    }

    return build();
}

// Create ability instance
const user = { id: 1, role: 'user' };
const ability = defineAbilitiesFor(user);

// Check permissions
ability.can('read', 'Article');              // true
ability.can('update', 'Article', { authorId: 1 }); // true
ability.can('update', 'Article', { authorId: 2 }); // false
ability.can('manage', 'all');                // false (not admin)
```

## Core Concepts

### Actions

What users can do:
```javascript
can('read', 'Article')
can('create', 'Article')
can('update', 'Article')
can('delete', 'Article')
can('manage', 'Article')  // Shorthand for all actions
```

### Subjects

Resources being accessed:
```javascript
can('read', 'Article')     // Subject type
can('read', article)       // Subject instance
can('read', 'all')         // All subjects
```

### Conditions

Restrict permissions based on attributes:
```javascript
// Can update own articles
can('update', 'Article', { authorId: user.id })

// Can't delete published comments
cannot('delete', 'Comment', { published: true })

// Multiple conditions
can('read', 'Article', {
    published: true,
    category: 'public'
})
```

### Fields

Restrict access to specific fields:
```javascript
// Can read all Article fields
can('read', 'Article')

// Can update only these fields
can('update', 'Article', ['title', 'content'])

// Can't read sensitive fields
cannot('read', 'Article', ['salary', 'ssn'])
```

## TypeScript Support

```typescript
import { AbilityBuilder, Ability } from '@casl/ability';

type Actions = 'create' | 'read' | 'update' | 'delete';
type Subjects = 'Article' | 'Comment' | 'User' | 'all';

type AppAbility = Ability<[Actions, Subjects]>;

function defineAbilitiesFor(user: User): AppAbility {
    const { can, cannot, build } = new AbilityBuilder<AppAbility>(Ability);

    if (user.role === 'admin') {
        can('manage', 'all');
    } else {
        can('read', 'Article');
        can('update', 'Article', { authorId: user.id });
    }

    return build();
}

// Type-safe checks
ability.can('read', 'Article');    // ✓ Valid
ability.can('fly', 'Article');     // ✗ Type error
ability.can('read', 'Spaceship');  // ✗ Type error
```

## React Integration

### Setup

```javascript
import { createContext } from 'react';
import { createContextualCan } from '@casl/react';

export const AbilityContext = createContext();
export const Can = createContextualCan(AbilityContext.Consumer);
```

### Provider

```javascript
import { AbilityContext } from './Can';

function App() {
    const user = useCurrentUser();
    const ability = defineAbilitiesFor(user);

    return (
        <AbilityContext.Provider value={ability}>
            <YourApp />
        </AbilityContext.Provider>
    );
}
```

### Component Usage

```javascript
import { Can } from './Can';

function ArticleActions({ article }) {
    return (
        <div>
            <Can I="read" a="Article">
                <button>View</button>
            </Can>

            <Can I="update" this={article}>
                <button>Edit</button>
            </Can>

            <Can I="delete" this={article}>
                <button>Delete</button>
            </Can>
        </div>
    );
}
```

### Imperative Checks

```javascript
import { useAbility } from '@casl/react';
import { AbilityContext } from './Can';

function ArticleForm() {
    const ability = useAbility(AbilityContext);

    const handleSubmit = (article) => {
        if (ability.can('create', 'Article')) {
            // Create article
        } else {
            // Show error
        }
    };

    return <form onSubmit={handleSubmit}>...</form>;
}
```

## Vue Integration

### Setup (Vue 3)

```javascript
import { createApp } from 'vue';
import { abilitiesPlugin } from '@casl/vue';

const app = createApp(App);
const ability = defineAbilitiesFor(currentUser);

app.use(abilitiesPlugin, ability);
```

### Template Usage

```vue
<template>
  <div>
    <button v-if="$can('read', 'Article')">View</button>
    <button v-if="$can('update', article)">Edit</button>
    <button v-if="$can('delete', article)">Delete</button>
  </div>
</template>

<script>
export default {
  name: 'ArticleActions',
  props: ['article'],
};
</script>
```

### Composition API

```vue
<script setup>
import { useAbility } from '@casl/vue';

const ability = useAbility();
const canEdit = ability.can('update', article);
</script>

<template>
  <button v-if="canEdit">Edit</button>
</template>
```

## Angular Integration

### Module Setup

```typescript
import { NgModule } from '@angular/core';
import { AbilityModule } from '@casl/angular';
import { Ability, PureAbility } from '@casl/ability';

@NgModule({
  imports: [
    AbilityModule
  ],
  providers: [
    { provide: Ability, useValue: new Ability() },
    { provide: PureAbility, useExisting: Ability }
  ]
})
export class AppModule {}
```

### Component Usage

```typescript
import { Component } from '@angular/core';
import { Ability } from '@casl/ability';

@Component({
  selector: 'app-article',
  template: `
    <button *ngIf="ability.can('read', 'Article')">View</button>
    <button *ngIf="ability.can('update', article)">Edit</button>
    <button *ngIf="ability.can('delete', article)">Delete</button>
  `
})
export class ArticleComponent {
  constructor(public ability: Ability) {}
}
```

## Backend (Node.js/Express)

### Middleware

```javascript
import { defineAbilitiesFor } from './abilities';

function authorize(action, subject) {
    return (req, res, next) => {
        const ability = defineAbilitiesFor(req.user);

        if (ability.can(action, subject)) {
            next();
        } else {
            res.status(403).send('Forbidden');
        }
    };
}

// Apply to routes
app.get('/articles', authorize('read', 'Article'), (req, res) => {
    // Return articles
});

app.post('/articles', authorize('create', 'Article'), (req, res) => {
    // Create article
});

app.put('/articles/:id', async (req, res) => {
    const article = await Article.findById(req.params.id);
    const ability = defineAbilitiesFor(req.user);

    if (ability.can('update', article)) {
        // Update article
    } else {
        res.status(403).send('Forbidden');
    }
});
```

### Database Queries

Generate database queries from abilities:

```javascript
import { accessibleBy } from '@casl/mongoose';
import { Article } from './models';

async function getArticles(req, res) {
    const ability = defineAbilitiesFor(req.user);

    // Find only articles user can read
    const articles = await Article.find(accessibleBy(ability).Article);

    res.json(articles);
}
```

## Advanced Patterns

### Complex Conditions

```javascript
const { can } = new AbilityBuilder(Ability);

// Nested conditions
can('read', 'Article', {
    $or: [
        { published: true },
        { authorId: user.id }
    ]
});

// Array conditions
can('read', 'Article', {
    tags: { $in: user.interests }
});

// Comparison operators
can('update', 'Article', {
    createdAt: { $gt: new Date('2023-01-01') }
});
```

### Field-Level Permissions

```javascript
const { can } = new AbilityBuilder(Ability);

// Can read all fields
can('read', 'User');

// Can update only name and email
can('update', 'User', ['name', 'email'], { id: user.id });

// Cannot read sensitive fields
cannot('read', 'User', ['password', 'ssn']);

// Check field access
ability.can('read', 'User', 'password');  // false
```

### Inverted Abilities

```javascript
// Start with full access
can('manage', 'all');

// Remove specific permissions
cannot('delete', 'Article', { published: true });
cannot('update', 'User', { role: 'admin' });
```

### Dynamic Abilities

Update abilities at runtime:

```javascript
import { Ability } from '@casl/ability';

const ability = new Ability();

// Update abilities
function updateAbilities(user) {
    const { can, rules } = new AbilityBuilder(Ability);

    if (user.role === 'admin') {
        can('manage', 'all');
    } else {
        can('read', 'Article');
    }

    ability.update(rules);
}

// Abilities change when user changes
updateAbilities(newUser);
```

## Database Integration

### Mongoose

```javascript
import { accessibleBy } from '@casl/mongoose';
import mongoose from 'mongoose';

const Article = mongoose.model('Article', articleSchema);

// Find accessible articles
const articles = await Article.find(accessibleBy(ability, 'read'));

// Find + populate
const articles = await Article
    .find(accessibleBy(ability, 'read'))
    .populate('author');

// Custom action
const articles = await Article.find(accessibleBy(ability, 'moderate'));
```

### Prisma

```javascript
import { accessibleBy } from '@casl/prisma';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// Get accessible articles
const articles = await prisma.article.findMany({
    where: accessibleBy(ability, 'read').Article
});
```

### TypeORM

```javascript
import { accessibleBy } from '@casl/typeorm';
import { Article } from './entities';

// Get query builder
const query = Article.createQueryBuilder('article');

// Apply permissions
const accessibleQuery = accessibleBy(ability, 'read').ofType(Article);
query.where(accessibleQuery);

const articles = await query.getMany();
```

## Testing

```javascript
import { defineAbilitiesFor } from './abilities';

describe('Abilities', () => {
    test('admin can manage all', () => {
        const admin = { role: 'admin' };
        const ability = defineAbilitiesFor(admin);

        expect(ability.can('manage', 'all')).toBe(true);
        expect(ability.can('delete', 'Article')).toBe(true);
    });

    test('user can update own articles', () => {
        const user = { id: 1, role: 'user' };
        const ability = defineAbilitiesFor(user);

        const ownArticle = { authorId: 1 };
        const otherArticle = { authorId: 2 };

        expect(ability.can('update', 'Article', ownArticle)).toBe(true);
        expect(ability.can('update', 'Article', otherArticle)).toBe(false);
    });

    test('cannot delete published comments', () => {
        const user = { id: 1, role: 'user' };
        const ability = defineAbilitiesFor(user);

        const publishedComment = { published: true };
        const draftComment = { published: false };

        expect(ability.can('delete', 'Comment', publishedComment)).toBe(false);
        expect(ability.can('delete', 'Comment', draftComment)).toBe(true);
    });
});
```

## Performance

### Caching

```javascript
import { Ability } from '@casl/ability';

// Cache ability instances per user
const abilityCache = new Map();

function getAbilityFor(user) {
    const cacheKey = `${user.id}-${user.role}`;

    if (!abilityCache.has(cacheKey)) {
        abilityCache.set(cacheKey, defineAbilitiesFor(user));
    }

    return abilityCache.get(cacheKey);
}
```

### Lazy Loading

```javascript
// Only define abilities when needed
let ability;

function getAbility() {
    if (!ability) {
        ability = defineAbilitiesFor(currentUser);
    }
    return ability;
}
```

## Best Practices

1. **Centralize Definitions**: Keep all ability definitions in one place
2. **Use TypeScript**: Type-safe permissions prevent errors
3. **Test Thoroughly**: Write tests for all permission scenarios
4. **Share Logic**: Reuse same abilities in frontend and backend
5. **Cache Abilities**: Cache ability instances per user
6. **Field Permissions**: Use field-level restrictions when needed
7. **Database Queries**: Use accessibleBy for filtering
8. **Update Dynamically**: Update abilities when user role changes
9. **Document Permissions**: Clear comments for complex rules
10. **Principle of Least Privilege**: Grant minimum necessary permissions

## Comparison

| Feature | CASL | OPA | Casbin |
|---------|------|-----|--------|
| **JavaScript Focus** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **TypeScript** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Frontend** | ⭐⭐⭐⭐⭐ | ⭐ | ⭐⭐ |
| **Database Integration** | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ |
| **Performance** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Flexibility** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Cloud-Native** | ⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |

## Real-World Example

```javascript
// abilities.js
import { AbilityBuilder, Ability } from '@casl/ability';

export function defineAbilitiesFor(user) {
    const { can, cannot, build } = new AbilityBuilder(Ability);

    if (user.role === 'admin') {
        can('manage', 'all');
    } else if (user.role === 'moderator') {
        can('read', 'all');
        can('update', 'Article', { status: 'pending' });
        can('delete', 'Comment', { flagged: true });
    } else {
        can('read', 'Article', { published: true });
        can('create', 'Article');
        can('update', 'Article', { authorId: user.id });
        can('delete', 'Article', { authorId: user.id, published: false });

        can('create', 'Comment');
        can('update', 'Comment', { authorId: user.id });
        cannot('delete', 'Comment', { published: true });
    }

    return build();
}
```

## Further Resources

- **Documentation**: [casl.js.org/v6/en](https://casl.js.org/v6/en/)
- **Examples**: [github.com/stalniy/casl-examples](https://github.com/stalniy/casl-examples)
- **Blog**: [medium.com/@sergiy.stotskiy](https://medium.com/@sergiy.stotskiy)

## Community

- **Gitter**: [gitter.im/stalniy-casl](https://gitter.im/stalniy-casl/casl)
- **GitHub Issues**: [github.com/stalniy/casl/issues](https://github.com/stalniy/casl/issues)
- **Stack Overflow**: Tag `casl`

## Next Steps

- Review [ABAC Concepts](../../fundamentals/concepts/abac.md)
- Understand [RBAC Concepts](../../fundamentals/concepts/rbac.md)
- Compare with other frameworks in [Comparative Analysis](../../COMPARISON.md)
- Explore backend alternatives: [OPA](../opa/README.md), [Casbin](../casbin/README.md)
