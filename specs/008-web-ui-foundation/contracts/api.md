# API Contract: Web UI Foundation

## Base URL

`http://{host}:{port}` (default: `http://127.0.0.1:8484`)

## Endpoints

### Health Check

```
GET /api/health
```

**Response** `200 OK`:
```json
{
  "status": "ok",
  "version": "0.21.0",
  "database": "connected"
}
```

**Response** `503 Service Unavailable` (database unreachable):
```json
{
  "status": "degraded",
  "version": "0.21.0",
  "database": "disconnected"
}
```

## SPA Serving

### Static Assets

```
GET /assets/*
```

Serves compiled frontend files (JS bundles, CSS, fonts, images) from `ziran/interfaces/web/static/assets/`.

### SPA Fallback

```
GET /{any_path}
```

Any request that does not match `/api/*` or `/assets/*` returns `index.html` with `200 OK`. This enables client-side routing (React Router).

**When static assets are missing** (UI not built/installed):

```
GET /
```

**Response** `200 OK` with plain HTML:
```html
<html>
<body>
  <h1>Ziran Web UI</h1>
  <p>Frontend assets not found. Build the UI or install with: pip install ziran[ui]</p>
</body>
</html>
```

## Error Format

All API errors follow a consistent format:

```json
{
  "detail": "Human-readable error message"
}
```

Standard HTTP status codes: 400 (bad request), 404 (not found), 500 (server error), 503 (service unavailable).
