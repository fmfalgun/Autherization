package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/gorilla/mux"
)

type Server struct {
	enforcer *casbin.Enforcer
	router   *mux.Router
	mu       sync.RWMutex
	documents map[int]Document
	nextID   int
}

type Document struct {
	ID      int    `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
	Owner   string `json:"owner"`
}

type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func main() {
	// Initialize Casbin enforcer
	enforcer, err := casbin.NewEnforcer("model.conf", "policy.csv")
	if err != nil {
		log.Fatalf("Failed to initialize Casbin: %v", err)
	}

	// Enable auto-save to persist policy changes
	enforcer.EnableAutoSave(true)

	log.Println("Casbin enforcer initialized successfully")

	// Create server
	server := &Server{
		enforcer:  enforcer,
		router:    mux.NewRouter(),
		documents: make(map[int]Document),
		nextID:    1,
	}

	// Add some sample documents
	server.addSampleData()

	// Setup routes
	server.setupRoutes()

	// Start server
	addr := ":8080"
	log.Printf("Server starting on %s", addr)
	log.Printf("Try: curl http://localhost:8080/health")
	if err := http.ListenAndServe(addr, server.router); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func (s *Server) setupRoutes() {
	// Public routes
	s.router.HandleFunc("/health", s.healthHandler).Methods("GET")
	s.router.HandleFunc("/", s.homeHandler).Methods("GET")

	// API routes with authorization
	api := s.router.PathPrefix("/api").Subrouter()
	api.Use(s.authorizationMiddleware)

	// Document endpoints
	api.HandleFunc("/documents", s.listDocumentsHandler).Methods("GET")
	api.HandleFunc("/documents", s.createDocumentHandler).Methods("POST")
	api.HandleFunc("/documents/{id}", s.getDocumentHandler).Methods("GET")
	api.HandleFunc("/documents/{id}", s.updateDocumentHandler).Methods("PUT")
	api.HandleFunc("/documents/{id}", s.deleteDocumentHandler).Methods("DELETE")

	// User endpoints
	api.HandleFunc("/users", s.listUsersHandler).Methods("GET")
	api.HandleFunc("/users", s.createUserHandler).Methods("POST")
	api.HandleFunc("/users/{id}", s.deleteUserHandler).Methods("DELETE")

	// Permission endpoints
	api.HandleFunc("/permissions/{user}", s.getUserPermissionsHandler).Methods("GET")
	s.router.HandleFunc("/api/policies", s.listPoliciesHandler).Methods("GET")
}

func (s *Server) authorizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user from header (in production, use JWT or session)
		user := r.Header.Get("X-User")
		if user == "" {
			sendError(w, http.StatusUnauthorized, "Missing X-User header")
			return
		}

		// Extract resource and action
		resource := r.URL.Path
		action := r.Method

		// Check permission
		allowed, err := s.enforcer.Enforce(user, resource, action)
		if err != nil {
			log.Printf("Authorization check failed: %v", err)
			sendError(w, http.StatusInternalServerError, "Authorization check failed")
			return
		}

		if !allowed {
			log.Printf("Access denied: user=%s, resource=%s, action=%s", user, resource, action)
			sendError(w, http.StatusForbidden, "Insufficient permissions")
			return
		}

		log.Printf("Access granted: user=%s, resource=%s, action=%s", user, resource, action)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	sendSuccess(w, map[string]string{
		"status": "healthy",
		"service": "casbin-rbac-example",
	})
}

func (s *Server) homeHandler(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>Casbin RBAC Example</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        .endpoint { background: #f4f4f4; padding: 10px; margin: 10px 0; border-left: 4px solid #007bff; }
        code { background: #e9ecef; padding: 2px 5px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>Casbin RBAC Example API</h1>
    <p>This is a demonstration of Role-Based Access Control using Casbin.</p>

    <h2>Available Endpoints:</h2>

    <div class="endpoint">
        <strong>GET /health</strong><br>
        Health check endpoint (no auth required)
    </div>

    <div class="endpoint">
        <strong>GET /api/documents</strong><br>
        List all documents (requires user, manager, or admin role)<br>
        <code>curl -H "X-User: bob" http://localhost:8080/api/documents</code>
    </div>

    <div class="endpoint">
        <strong>POST /api/documents</strong><br>
        Create document (requires manager or admin role)<br>
        <code>curl -X POST -H "X-User: alice" -H "Content-Type: application/json" -d '{"title":"Test","content":"Hello"}' http://localhost:8080/api/documents</code>
    </div>

    <div class="endpoint">
        <strong>DELETE /api/documents/:id</strong><br>
        Delete document (requires admin role)<br>
        <code>curl -X DELETE -H "X-User: admin_user" http://localhost:8080/api/documents/1</code>
    </div>

    <div class="endpoint">
        <strong>GET /api/policies</strong><br>
        View all policies (no auth required for demo)
    </div>

    <h2>Test Users:</h2>
    <ul>
        <li><strong>alice</strong> - manager role</li>
        <li><strong>bob</strong> - user role</li>
        <li><strong>charlie</strong> - user role</li>
        <li><strong>admin_user</strong> - admin role</li>
    </ul>
</body>
</html>
`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func (s *Server) listDocumentsHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	docs := make([]Document, 0, len(s.documents))
	for _, doc := range s.documents {
		docs = append(docs, doc)
	}

	sendSuccess(w, docs)
}

func (s *Server) createDocumentHandler(w http.ResponseWriter, r *http.Request) {
	var doc Document
	if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
		sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	s.mu.Lock()
	doc.ID = s.nextID
	s.nextID++
	doc.Owner = r.Header.Get("X-User")
	s.documents[doc.ID] = doc
	s.mu.Unlock()

	sendSuccess(w, doc)
}

func (s *Server) getDocumentHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, doc := range s.documents {
		if fmt.Sprintf("%d", doc.ID) == id {
			sendSuccess(w, doc)
			return
		}
	}

	sendError(w, http.StatusNotFound, "Document not found")
}

func (s *Server) updateDocumentHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var updates Document
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for k, doc := range s.documents {
		if fmt.Sprintf("%d", doc.ID) == id {
			if updates.Title != "" {
				doc.Title = updates.Title
			}
			if updates.Content != "" {
				doc.Content = updates.Content
			}
			s.documents[k] = doc
			sendSuccess(w, doc)
			return
		}
	}

	sendError(w, http.StatusNotFound, "Document not found")
}

func (s *Server) deleteDocumentHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	s.mu.Lock()
	defer s.mu.Unlock()

	for k, doc := range s.documents {
		if fmt.Sprintf("%d", doc.ID) == id {
			delete(s.documents, k)
			sendSuccess(w, map[string]string{"message": "Document deleted"})
			return
		}
	}

	sendError(w, http.StatusNotFound, "Document not found")
}

func (s *Server) listUsersHandler(w http.ResponseWriter, r *http.Request) {
	users := []map[string]interface{}{
		{"username": "alice", "role": "manager"},
		{"username": "bob", "role": "user"},
		{"username": "charlie", "role": "user"},
		{"username": "admin_user", "role": "admin"},
	}
	sendSuccess(w, users)
}

func (s *Server) createUserHandler(w http.ResponseWriter, r *http.Request) {
	sendSuccess(w, map[string]string{"message": "User creation not implemented in this demo"})
}

func (s *Server) deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	sendSuccess(w, map[string]string{"message": "User deletion not implemented in this demo"})
}

func (s *Server) getUserPermissionsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	user := vars["user"]

	// Get implicit permissions for user (including inherited)
	permissions := s.enforcer.GetImplicitPermissionsForUser(user)

	// Get roles for user
	roles := s.enforcer.GetRolesForUser(user)

	result := map[string]interface{}{
		"user":        user,
		"roles":       roles,
		"permissions": permissions,
	}

	sendSuccess(w, result)
}

func (s *Server) listPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	policies := s.enforcer.GetPolicy()
	grouping := s.enforcer.GetGroupingPolicy()

	result := map[string]interface{}{
		"policies": policies,
		"roles":    grouping,
	}

	sendSuccess(w, result)
}

func (s *Server) addSampleData() {
	s.documents[1] = Document{
		ID:      1,
		Title:   "Getting Started Guide",
		Content: "Welcome to Casbin RBAC",
		Owner:   "alice",
	}
	s.documents[2] = Document{
		ID:      2,
		Title:   "API Documentation",
		Content: "RESTful API endpoints",
		Owner:   "bob",
	}
	s.documents[3] = Document{
		ID:      3,
		Title:   "Security Best Practices",
		Content: "Authorization guidelines",
		Owner:   "admin_user",
	}
	s.nextID = 4
}

func sendSuccess(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Data:    data,
	})
}

func sendError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{
		Success: false,
		Error:   message,
	})
}
