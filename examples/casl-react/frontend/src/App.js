import React, { useState, useEffect, createContext, useContext } from 'react';
import { createContextualCan } from '@casl/react';
import { buildAbilityFor, defaultAbility } from './abilities';
import './App.css';

// API URL
const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:3001/api';

// Ability Context
const AbilityContext = createContext(defaultAbility);
const Can = createContextualCan(AbilityContext.Consumer);

// Auth Context
const AuthContext = createContext({
  user: null,
  token: null,
  login: () => {},
  logout: () => {}
});

function App() {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [ability, setAbility] = useState(defaultAbility);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check if user is logged in
    if (token) {
      fetch(`${API_URL}/auth/me`, {
        headers: { 'Authorization': `Bearer ${token}` }
      })
        .then(res => res.json())
        .then(data => {
          if (data.user) {
            setUser(data.user);
            setAbility(buildAbilityFor(data.abilities));
          } else {
            logout();
          }
        })
        .catch(() => logout())
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, [token]);

  const login = async (username, password) => {
    const response = await fetch(`${API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Login failed');
    }

    setUser(data.user);
    setToken(data.token);
    setAbility(buildAbilityFor(data.abilities));
    localStorage.setItem('token', data.token);
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    setAbility(defaultAbility);
    localStorage.removeItem('token');
  };

  if (loading) {
    return <div className="loading">Loading...</div>;
  }

  return (
    <AuthContext.Provider value={{ user, token, login, logout }}>
      <AbilityContext.Provider value={ability}>
        <div className="App">
          <Header />
          <main className="main-content">
            {user ? <Dashboard /> : <Login />}
          </main>
        </div>
      </AbilityContext.Provider>
    </AuthContext.Provider>
  );
}

function Header() {
  const { user, logout } = useContext(AuthContext);

  return (
    <header className="header">
      <h1>CASL React Authorization Demo</h1>
      {user && (
        <div className="user-info">
          <span>Welcome, {user.name} ({user.role})</span>
          <button onClick={logout} className="btn btn-secondary">Logout</button>
        </div>
      )}
    </header>
  );
}

function Login() {
  const { login } = useContext(AuthContext);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await login(username, password);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const quickLogin = (user, pass) => {
    setUsername(user);
    setPassword(pass);
  };

  return (
    <div className="login-container">
      <div className="login-box">
        <h2>Login</h2>

        {error && <div className="error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              disabled={loading}
            />
          </div>

          <button type="submit" className="btn btn-primary" disabled={loading}>
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>

        <div className="quick-login">
          <p>Quick login:</p>
          <button onClick={() => quickLogin('admin', 'admin123')} className="btn btn-link">
            Admin
          </button>
          <button onClick={() => quickLogin('alice', 'alice123')} className="btn btn-link">
            Alice (Editor)
          </button>
          <button onClick={() => quickLogin('bob', 'bob123')} className="btn btn-link">
            Bob (Viewer)
          </button>
        </div>
      </div>
    </div>
  );
}

function Dashboard() {
  return (
    <div className="dashboard">
      <PostList />
    </div>
  );
}

function PostList() {
  const { token } = useContext(AuthContext);
  const ability = useContext(AbilityContext);
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateForm, setShowCreateForm] = useState(false);

  const loadPosts = async () => {
    setLoading(true);
    try {
      const headers = token ? { 'Authorization': `Bearer ${token}` } : {};
      const response = await fetch(`${API_URL}/posts`, { headers });
      const data = await response.json();
      setPosts(data.posts || []);
    } catch (error) {
      console.error('Error loading posts:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPosts();
  }, [token]);

  const handlePostCreated = (newPost) => {
    setPosts([...posts, newPost]);
    setShowCreateForm(false);
  };

  const handlePostUpdated = (updatedPost) => {
    setPosts(posts.map(p => p.id === updatedPost.id ? updatedPost : p));
  };

  const handlePostDeleted = (postId) => {
    setPosts(posts.filter(p => p.id !== postId));
  };

  if (loading) {
    return <div className="loading">Loading posts...</div>;
  }

  return (
    <div className="post-list">
      <div className="post-list-header">
        <h2>Posts</h2>
        <Can I="create" a="Post">
          <button
            onClick={() => setShowCreateForm(!showCreateForm)}
            className="btn btn-primary"
          >
            {showCreateForm ? 'Cancel' : 'Create Post'}
          </button>
        </Can>
      </div>

      {showCreateForm && (
        <PostForm onSuccess={handlePostCreated} onCancel={() => setShowCreateForm(false)} />
      )}

      {posts.length === 0 ? (
        <p>No posts available</p>
      ) : (
        posts.map(post => (
          <Post
            key={post.id}
            post={post}
            onUpdate={handlePostUpdated}
            onDelete={handlePostDeleted}
          />
        ))
      )}
    </div>
  );
}

function Post({ post, onUpdate, onDelete }) {
  const { token } = useContext(AuthContext);
  const ability = useContext(AbilityContext);
  const [isEditing, setIsEditing] = useState(false);
  const [title, setTitle] = useState(post.title);
  const [content, setContent] = useState(post.content);

  const handleUpdate = async (e) => {
    e.preventDefault();

    try {
      const response = await fetch(`${API_URL}/posts/${post.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ title, content })
      });

      const data = await response.json();

      if (response.ok) {
        onUpdate(data.post);
        setIsEditing(false);
      } else {
        alert(data.error);
      }
    } catch (error) {
      alert('Error updating post');
    }
  };

  const handleDelete = async () => {
    if (!window.confirm('Are you sure you want to delete this post?')) {
      return;
    }

    try {
      const response = await fetch(`${API_URL}/posts/${post.id}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        onDelete(post.id);
      } else {
        const data = await response.json();
        alert(data.error);
      }
    } catch (error) {
      alert('Error deleting post');
    }
  };

  const postSubject = { ...post, __type: 'Post' };

  return (
    <div className="post">
      {isEditing ? (
        <form onSubmit={handleUpdate}>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="form-control"
          />
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            className="form-control"
            rows="3"
          />
          <div className="post-actions">
            <button type="submit" className="btn btn-primary">Save</button>
            <button type="button" onClick={() => setIsEditing(false)} className="btn btn-secondary">
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <>
          <h3>{post.title}</h3>
          <p>{post.content}</p>
          <div className="post-meta">
            By {post.author} • {new Date(post.createdAt).toLocaleDateString()}
            {!post.isPublic && <span className="badge">Private</span>}
          </div>
          <div className="post-actions">
            <Can I="update" this={postSubject}>
              <button onClick={() => setIsEditing(true)} className="btn btn-secondary">
                Edit
              </button>
            </Can>
            <Can I="delete" this={postSubject}>
              <button onClick={handleDelete} className="btn btn-danger">
                Delete
              </button>
            </Can>
          </div>
        </>
      )}
    </div>
  );
}

function PostForm({ onSuccess, onCancel }) {
  const { token } = useContext(AuthContext);
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [isPublic, setIsPublic] = useState(true);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await fetch(`${API_URL}/posts`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ title, content, isPublic })
      });

      const data = await response.json();

      if (response.ok) {
        onSuccess(data.post);
        setTitle('');
        setContent('');
        setIsPublic(true);
      } else {
        alert(data.error);
      }
    } catch (error) {
      alert('Error creating post');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="post-form">
      <h3>Create New Post</h3>
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label>Title</label>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            required
            disabled={loading}
            className="form-control"
          />
        </div>

        <div className="form-group">
          <label>Content</label>
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            required
            disabled={loading}
            rows="4"
            className="form-control"
          />
        </div>

        <div className="form-group">
          <label>
            <input
              type="checkbox"
              checked={isPublic}
              onChange={(e) => setIsPublic(e.target.checked)}
              disabled={loading}
            />
            {' '}Public post
          </label>
        </div>

        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={loading}>
            {loading ? 'Creating...' : 'Create Post'}
          </button>
          <button type="button" onClick={onCancel} className="btn btn-secondary" disabled={loading}>
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}

export default App;
export { Can };
