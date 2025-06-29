# Active Directory Authentication Middleware Example

This middleware integrates with an `entserver-activedirectory` service to provide Active Directory-based authorization for Traefik routes.

## Configuration

### Static Configuration (traefik.yml)
```yaml
api:
  dashboard: true

entryPoints:
  web:
    address: ":80"

providers:
  file:
    filename: dynamic.yml
    watch: true
```

### Dynamic Configuration (dynamic.yml)
```yaml
http:
  middlewares:
    ad-auth:
      activeDirectoryAuth:
        serverURL: "http://entserver-activedirectory:8080"
        eonID: "EON-123456"
        env: "production"
        action: "read"
        userIDHeader: "X-User-ID"
        removeHeader: false
        timeout: "5s"

  routers:
    protected-app:
      rule: "Host(`app.example.com`)"
      service: "app-service"
      middlewares:
        - "ad-auth"

  services:
    app-service:
      loadBalancer:
        servers:
          - url: "http://app:8080"
```

### Docker Compose Example
```yaml
version: '3.8'

services:
  traefik:
    image: traefik:v2.11
    command:
      - "--providers.file.filename=/etc/traefik/dynamic.yml"
      - "--providers.file.watch=true"
      - "--entrypoints.web.address=:80"
      - "--api.dashboard=true"
    ports:
      - "80:80"
      - "8080:8080"
    volumes:
      - ./traefik.yml:/etc/traefik/traefik.yml
      - ./dynamic.yml:/etc/traefik/dynamic.yml
    depends_on:
      - entserver-activedirectory

  entserver-activedirectory:
    image: your-org/entserver-activedirectory:latest
    ports:
      - "8081:8080"
    environment:
      - GRPC_PORT=21001
      - LOG_LEVEL=INFO
      - TLS_OPTIONS_TLS=none
    # Configure your entserver-activedirectory service here

  app:
    image: your-app:latest
    ports:
      - "8082:8080"
    # Your application that needs AD protection
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `serverURL` | string | **required** | URL of the entserver-activedirectory service |
| `eonID` | string | **required** | EON identifier for entitlement checking |
| `env` | string | **required** | Environment identifier (e.g., "dev", "staging", "production") |
| `action` | string | **required** | Action identifier (e.g., "read", "write", "admin") |
| `userIDHeader` | string | `X-User-ID` | HTTP header containing the user ID |
| `removeHeader` | bool | `false` | Whether to remove the UserID header before forwarding to backend |
| `timeout` | duration | `5s` | Timeout for entitlement service requests |

## How It Works

1. **Request Processing**: When a request comes in, the middleware extracts the user ID from the specified header (default: `X-User-ID`).

2. **User ID Cleanup**: If the user ID contains a domain prefix (e.g., `DOMAIN\username`), it strips the domain part and uses only the username.

3. **Entitlement Check**: The middleware sends a POST request to the entserver-activedirectory service with:
   ```json
   {
     "userID": "username",
     "eonID": "EON-123456",
     "env": "production",
     "action": "read"
   }
   ```

4. **Authorization Decision**: Based on the response from the entitlement service:
   - `{"entitled": true}` → Request is forwarded to the backend
   - `{"entitled": false}` → Returns 403 Forbidden
   - Service error → Returns 500 Internal Server Error

5. **Header Management**: Optionally removes the UserID header before forwarding the request to the backend service.

## Usage Scenarios

### Basic Protection
Protect a service with read access:
```yaml
middlewares:
  basic-ad-auth:
    activeDirectoryAuth:
      serverURL: "http://entserver:8080"
      eonID: "APP-READ"
      env: "prod"
      action: "read"
```

### Admin-Only Access
Protect admin endpoints with elevated permissions:
```yaml
middlewares:
  admin-ad-auth:
    activeDirectoryAuth:
      serverURL: "http://entserver:8080"
      eonID: "APP-ADMIN"
      env: "prod"
      action: "admin"
      timeout: "10s"
```

### Custom User Header
Use a custom header for user identification:
```yaml
middlewares:
  custom-header-auth:
    activeDirectoryAuth:
      serverURL: "http://entserver:8080"
      eonID: "APP-READ"
      env: "prod"
      action: "read"
      userIDHeader: "X-Username"
      removeHeader: true
```

## Integration with entserver-activedirectory

The middleware expects the entserver-activedirectory service to expose an endpoint at `/entitlement` that accepts POST requests with the entitlement request JSON and returns a response indicating whether the user is entitled.

### Request Format
```json
{
  "userID": "username",
  "eonID": "EON-123456",
  "env": "production",
  "action": "read"
}
```

### Response Format
```json
{
  "entitled": true,
  "message": "Access granted"
}
```

## Error Handling

- **Missing UserID Header**: Returns 401 Unauthorized
- **Entitlement Service Unavailable**: Returns 500 Internal Server Error
- **Access Denied**: Returns 403 Forbidden
- **Invalid Configuration**: Middleware fails to start

## Logging

The middleware provides detailed logging at debug level, including:
- User ID extraction and processing
- Entitlement service requests and responses
- Authorization decisions
- Error conditions

Enable debug logging in Traefik to see detailed middleware activity:
```yaml
log:
  level: DEBUG
```
