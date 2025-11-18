.PHONY: help up down logs clean install-backend install-frontend install build test

help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

up: ## Start both frontend and backend with Docker
	@echo "Starting CASL React app..."
	docker-compose up --build -d
	@echo "✅ Frontend: http://localhost:3000"
	@echo "✅ Backend:  http://localhost:3001"

down: ## Stop all services
	@echo "Stopping services..."
	docker-compose down
	@echo "✅ Services stopped"

logs: ## Show logs
	docker-compose logs -f

logs-backend: ## Show backend logs
	docker-compose logs -f backend

logs-frontend: ## Show frontend logs
	docker-compose logs -f frontend

clean: ## Clean up everything
	@echo "Cleaning up..."
	docker-compose down -v
	rm -rf backend/node_modules frontend/node_modules
	@echo "✅ Cleanup complete"

install: install-backend install-frontend ## Install all dependencies

install-backend: ## Install backend dependencies
	@echo "Installing backend dependencies..."
	cd backend && npm install
	@echo "✅ Backend dependencies installed"

install-frontend: ## Install frontend dependencies
	@echo "Installing frontend dependencies..."
	cd frontend && npm install
	@echo "✅ Frontend dependencies installed"

build: ## Build Docker images
	@echo "Building Docker images..."
	docker-compose build
	@echo "✅ Build complete"

dev-backend: ## Run backend locally (requires Node.js)
	@echo "Starting backend in dev mode..."
	cd backend && npm run dev

dev-frontend: ## Run frontend locally (requires Node.js)
	@echo "Starting frontend in dev mode..."
	cd frontend && npm start

test-backend: ## Run backend tests
	cd backend && npm test

test-frontend: ## Run frontend tests
	cd frontend && npm test

health: ## Check backend health
	@curl -s http://localhost:3001/health | python3 -m json.tool
