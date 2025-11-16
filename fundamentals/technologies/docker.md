# Docker for Authorization Services

## Overview

**Docker** is a platform for developing, shipping, and running applications in containers. For authorization systems, Docker provides consistent deployment, easy scaling, and isolation of policy engines and authorization services.

## Why Docker for Authorization?

- **Consistency**: Same environment dev to production
- **Isolation**: Separate authorization logic from applications
- **Scalability**: Easy to scale policy engines horizontally
- **Portability**: Run anywhere Docker is supported
- **Security**: Containerized isolation

## Running Authorization Services in Docker

### OPA (Open Policy Agent)

#### Basic OPA Container

```bash
# Pull official OPA image
docker pull openpolicyagent/opa:latest

# Run OPA server
docker run -d \
  --name opa \
  -p 8181:8181 \
  openpolicyagent/opa:latest \
  run --server --log-level=info
```

#### OPA with Policies

```bash
# Run with mounted policy directory
docker run -d \
  --name opa \
  -p 8181:8181 \
  -v $(pwd)/policies:/policies \
  openpolicyagent/opa:latest \
  run --server --log-level=info /policies
```

#### OPA with Bundle Server

```bash
# Run with bundle configuration
docker run -d \
  --name opa \
  -p 8181:8181 \
  -v $(pwd)/config.yaml:/config.yaml \
  openpolicyagent/opa:latest \
  run --server --config-file=/config.yaml
```

### Keycloak

```bash
# Run Keycloak
docker run -d \
  --name keycloak \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest \
  start-dev
```

### SpiceDB

```bash
# Run SpiceDB with in-memory datastore (development)
docker run -d \
  --name spicedb \
  -p 50051:50051 \
  authzed/spicedb serve \
  --grpc-preshared-key "dev-key" \
  --datastore-engine memory

# Run with PostgreSQL (production)
docker run -d \
  --name spicedb \
  -p 50051:50051 \
  --link postgres:postgres \
  authzed/spicedb serve \
  --grpc-preshared-key "your-secret-key" \
  --datastore-engine postgres \
  --datastore-conn-uri "postgres://user:pass@postgres:5432/spicedb"
```

### Casbin

```bash
# Build custom Casbin service
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o casbin-server .

FROM alpine:latest
COPY --from=builder /app/casbin-server /casbin-server
COPY model.conf /model.conf
COPY policy.csv /policy.csv
EXPOSE 8080
CMD ["/casbin-server"]
```

## Docker Compose for Authorization Stack

### OPA + Application

```yaml
# docker-compose.yml
version: '3.8'

services:
  opa:
    image: openpolicyagent/opa:latest
    command:
      - "run"
      - "--server"
      - "--log-level=info"
      - "/policies"
    ports:
      - "8181:8181"
    volumes:
      - ./policies:/policies
    healthcheck:
      test: ["CMD", "wget", "--spider", "http://localhost:8181/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  app:
    build: ./app
    ports:
      - "3000:3000"
    environment:
      - OPA_URL=http://opa:8181
    depends_on:
      - opa
```

### Full Authorization Stack

```yaml
version: '3.8'

services:
  # PostgreSQL for data persistence
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: authz
      POSTGRES_USER: authz
      POSTGRES_PASSWORD: secret
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U authz"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Keycloak for identity & access management
  keycloak:
    image: quay.io/keycloak/keycloak:latest
    command: start-dev
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/authz
      KC_DB_USERNAME: authz
      KC_DB_PASSWORD: secret
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
    ports:
      - "8080:8080"
    depends_on:
      postgres:
        condition: service_healthy

  # OPA for policy enforcement
  opa:
    image: openpolicyagent/opa:latest
    command:
      - "run"
      - "--server"
      - "--addr=0.0.0.0:8181"
      - "/policies"
    ports:
      - "8181:8181"
    volumes:
      - ./policies:/policies:ro
    environment:
      - OPA_LOG_LEVEL=debug

  # Application
  app:
    build: ./app
    ports:
      - "3000:3000"
    environment:
      - KEYCLOAK_URL=http://keycloak:8080
      - OPA_URL=http://opa:8181
      - DATABASE_URL=postgresql://authz:secret@postgres:5432/authz
    depends_on:
      - postgres
      - keycloak
      - opa

volumes:
  postgres_data:
```

## Dockerfile Best Practices

### Multi-Stage Build for Go Authorization Service

```dockerfile
# Build stage
FROM golang:1.21-alpine AS builder

# Install dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-w -s" -o authz-service .

# Final stage
FROM scratch

# Copy CA certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary
COPY --from=builder /build/authz-service /authz-service

# Copy policies
COPY policies /policies

# Non-root user
USER 65534:65534

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/authz-service", "healthcheck"]

# Run
ENTRYPOINT ["/authz-service"]
CMD ["serve"]
```

### Optimized OPA Image

```dockerfile
FROM openpolicyagent/opa:latest-rootless

# Copy policies
COPY --chown=1000:1000 policies /policies

# Copy data
COPY --chown=1000:1000 data.json /data.json

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8181/health || exit 1

# Run as non-root
USER 1000:1000

# Expose port
EXPOSE 8181

# Start OPA
ENTRYPOINT ["/opa"]
CMD ["run", "--server", "--addr=:8181", "--log-level=info", "/policies"]
```

## Security Best Practices

### 1. Non-Root User

```dockerfile
# Create non-root user
RUN addgroup -g 1000 authz && \
    adduser -D -u 1000 -G authz authz

# Switch to non-root
USER authz:authz
```

### 2. Read-Only Filesystem

```yaml
services:
  opa:
    image: openpolicyagent/opa:latest
    read_only: true
    tmpfs:
      - /tmp
```

### 3. Resource Limits

```yaml
services:
  opa:
    image: openpolicyagent/opa:latest
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
```

### 4. Network Isolation

```yaml
services:
  opa:
    image: openpolicyagent/opa:latest
    networks:
      - internal
    # No ports exposed to host

  app:
    image: myapp:latest
    networks:
      - internal
      - external
    ports:
      - "3000:3000"

networks:
  internal:
    driver: bridge
    internal: true
  external:
    driver: bridge
```

### 5. Secrets Management

```yaml
services:
  opa:
    image: openpolicyagent/opa:latest
    secrets:
      - opa_config
    environment:
      - CONFIG_FILE=/run/secrets/opa_config

secrets:
  opa_config:
    file: ./config/opa_secret.yaml
```

## Production Deployment Patterns

### High Availability OPA

```yaml
version: '3.8'

services:
  opa:
    image: openpolicyagent/opa:latest
    command:
      - "run"
      - "--server"
      - "--config-file=/config/config.yaml"
    volumes:
      - ./config:/config:ro
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
      restart_policy:
        condition: on-failure
    networks:
      - opa_network

  # Load balancer
  nginx:
    image: nginx:alpine
    ports:
      - "8181:8181"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - opa
    networks:
      - opa_network

networks:
  opa_network:
    driver: overlay
```

### Kubernetes Deployment

```yaml
# OPA Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: opa
  labels:
    app: opa
spec:
  replicas: 3
  selector:
    matchLabels:
      app: opa
  template:
    metadata:
      labels:
        app: opa
    spec:
      containers:
      - name: opa
        image: openpolicyagent/opa:latest
        args:
          - "run"
          - "--server"
          - "--addr=:8181"
          - "/policies"
        ports:
        - containerPort: 8181
        volumeMounts:
        - name: policies
          mountPath: /policies
          readOnly: true
        livenessProbe:
          httpGet:
            path: /health
            port: 8181
          initialDelaySeconds: 5
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health?bundle=true
            port: 8181
          initialDelaySeconds: 5
          periodSeconds: 10
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 512Mi
      volumes:
      - name: policies
        configMap:
          name: opa-policies

---
# OPA Service
apiVersion: v1
kind: Service
metadata:
  name: opa
spec:
  selector:
    app: opa
  ports:
  - protocol: TCP
    port: 8181
    targetPort: 8181
```

## Monitoring and Logging

### Logging with Docker

```yaml
services:
  opa:
    image: openpolicyagent/opa:latest
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    # Or use syslog
    # logging:
    #   driver: "syslog"
    #   options:
    #     syslog-address: "tcp://192.168.0.42:123"
```

### Prometheus Metrics

```yaml
services:
  opa:
    image: openpolicyagent/opa:latest
    ports:
      - "8181:8181"
    labels:
      - "prometheus.scrape=true"
      - "prometheus.port=8181"
      - "prometheus.path=/metrics"

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
```

## Testing in Docker

### Integration Tests

```yaml
# docker-compose.test.yml
version: '3.8'

services:
  opa:
    image: openpolicyagent/opa:latest
    volumes:
      - ./policies:/policies

  test:
    build:
      context: .
      dockerfile: Dockerfile.test
    depends_on:
      - opa
    environment:
      - OPA_URL=http://opa:8181
    command: npm test
```

### Test Dockerfile

```dockerfile
FROM node:18-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .

CMD ["npm", "test"]
```

## Useful Commands

```bash
# View logs
docker logs opa

# Follow logs
docker logs -f opa

# Execute command in container
docker exec opa opa test /policies

# Inspect container
docker inspect opa

# View resource usage
docker stats opa

# Clean up
docker rm -f opa
docker system prune -a

# Export/Import images
docker save openpolicyagent/opa:latest > opa.tar
docker load < opa.tar

# Build with specific platform
docker build --platform linux/amd64 -t myapp .
```

## Further Reading

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)
- [OPA Docker Guide](https://www.openpolicyagent.org/docs/latest/docker/)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)

## Next Steps

- Learn [Go](./go.md) for building authorization services
- Explore [Kubernetes deployment](../../frameworks/opa/)
- Review [Zero Trust Architecture](../concepts/zero-trust.md)
