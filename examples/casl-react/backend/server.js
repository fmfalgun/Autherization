import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { defineAbilitiesFor, packRules } from './abilities.js';

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());

// In-memory data stores (use a real database in production)
const users = [
  {
    id: 1,
    username: 'admin',
    password: bcrypt.hashSync('admin123', 10),
    role: 'admin',
    name: 'Admin User',
    email: 'admin@example.com'
  },
  {
    id: 2,
    username: 'alice',
    password: bcrypt.hashSync('alice123', 10),
    role: 'editor',
    name: 'Alice Editor',
    email: 'alice@example.com'
  },
  {
    id: 3,
    username: 'bob',
    password: bcrypt.hashSync('bob123', 10),
    role: 'viewer',
    name: 'Bob Viewer',
    email: 'bob@example.com'
  }
];

let posts = [
  {
    id: 1,
    title: 'Welcome to CASL',
    content: 'This is a demo of authorization with CASL',
    authorId: 1,
    author: 'Admin User',
    isPublic: true,
    createdAt: new Date('2025-01-15')
  },
  {
    id: 2,
    title: 'Getting Started',
    content: 'Learn how to use CASL for authorization',
    authorId: 2,
    author: 'Alice Editor',
    isPublic: true,
    createdAt: new Date('2025-02-01')
  },
  {
    id: 3,
    title: 'Advanced Patterns',
    content: 'Complex authorization scenarios',
    authorId: 2,
    author: 'Alice Editor',
    isPublic: false,
    createdAt: new Date('2025-03-10')
  }
];

let nextPostId = 4;

// Authentication middleware
const requireAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.substring(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = users.find(u => u.id === decoded.id);

    if (!req.user) {
      return res.status(401).json({ error: 'User not found' });
    }

    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Routes

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'casl-backend' });
});

// Auth routes
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Generate JWT
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  // Define abilities for user
  const ability = defineAbilitiesFor(user);

  // Send user data (without password), token, and abilities
  const { password: _, ...userWithoutPassword } = user;

  res.json({
    user: userWithoutPassword,
    token,
    abilities: packRules(ability)
  });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const { password: _, ...userWithoutPassword } = req.user;
  const ability = defineAbilitiesFor(req.user);

  res.json({
    user: userWithoutPassword,
    abilities: packRules(ability)
  });
});

// Post routes
app.get('/api/posts', (req, res) => {
  // Public endpoint - anyone can view public posts
  // Authenticated users can see all posts
  const authHeader = req.headers.authorization;
  let user = null;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const token = authHeader.substring(7);
      const decoded = jwt.verify(token, JWT_SECRET);
      user = users.find(u => u.id === decoded.id);
    } catch (error) {
      // Invalid token, treat as guest
    }
  }

  const ability = defineAbilitiesFor(user);

  // Filter posts based on abilities
  const visiblePosts = posts.filter(post => ability.can('read', post));

  res.json({ posts: visiblePosts });
});

app.get('/api/posts/:id', (req, res) => {
  const post = posts.find(p => p.id === parseInt(req.params.id));

  if (!post) {
    return res.status(404).json({ error: 'Post not found' });
  }

  res.json({ post });
});

app.post('/api/posts', requireAuth, (req, res) => {
  const ability = defineAbilitiesFor(req.user);

  if (ability.cannot('create', 'Post')) {
    return res.status(403).json({ error: 'Forbidden: Cannot create posts' });
  }

  const { title, content, isPublic = true } = req.body;

  if (!title || !content) {
    return res.status(400).json({ error: 'Title and content required' });
  }

  const newPost = {
    id: nextPostId++,
    title,
    content,
    isPublic,
    authorId: req.user.id,
    author: req.user.name,
    createdAt: new Date()
  };

  posts.push(newPost);

  res.status(201).json({ post: newPost });
});

app.put('/api/posts/:id', requireAuth, (req, res) => {
  const post = posts.find(p => p.id === parseInt(req.params.id));

  if (!post) {
    return res.status(404).json({ error: 'Post not found' });
  }

  const ability = defineAbilitiesFor(req.user);

  // Create subject with Post type
  const subject = { ...post, __type: 'Post' };

  if (ability.cannot('update', subject)) {
    return res.status(403).json({ error: 'Forbidden: Cannot update this post' });
  }

  const { title, content, isPublic } = req.body;

  if (title !== undefined) post.title = title;
  if (content !== undefined) post.content = content;
  if (isPublic !== undefined) post.isPublic = isPublic;

  post.updatedAt = new Date();

  res.json({ post });
});

app.delete('/api/posts/:id', requireAuth, (req, res) => {
  const postIndex = posts.findIndex(p => p.id === parseInt(req.params.id));

  if (postIndex === -1) {
    return res.status(404).json({ error: 'Post not found' });
  }

  const post = posts[postIndex];
  const ability = defineAbilitiesFor(req.user);

  const subject = { ...post, __type: 'Post' };

  if (ability.cannot('delete', subject)) {
    return res.status(403).json({ error: 'Forbidden: Cannot delete this post' });
  }

  posts.splice(postIndex, 1);

  res.json({ message: 'Post deleted successfully' });
});

// User routes
app.get('/api/users', requireAuth, (req, res) => {
  const ability = defineAbilitiesFor(req.user);

  if (ability.cannot('read', 'User')) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  // Remove passwords
  const safeUsers = users.map(({ password, ...user }) => user);

  res.json({ users: safeUsers });
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log(`\nTest credentials:`);
  console.log(`  Admin:  admin / admin123`);
  console.log(`  Editor: alice / alice123`);
  console.log(`  Viewer: bob / bob123`);
});
