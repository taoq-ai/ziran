# CLI Contract: `ziran ui` Command

## Usage

```
ziran ui [OPTIONS]
```

## Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--host` | String | `127.0.0.1` | Server bind address |
| `--port` | Integer | `8484` | Server port |
| `--dev` | Flag | `false` | Enable development mode (CORS, auto-reload) |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ZIRAN_DATABASE_URL` | `postgresql+asyncpg://localhost:5432/ziran` | PostgreSQL connection URL |

## Behavior

### Normal Start
```
$ ziran ui
Ziran Web UI starting...
Dashboard: http://127.0.0.1:8484
Press Ctrl+C to stop.
```

### Development Mode
```
$ ziran ui --dev
Ziran Web UI starting in development mode...
Dashboard: http://127.0.0.1:8484
CORS enabled for all origins.
Auto-reload enabled.
Press Ctrl+C to stop.
```

### Missing Dependencies
```
$ ziran ui
Error: Web UI dependencies not installed.
Run: pip install ziran[ui]
```
Exit code: 1

### Database Connection Failure
```
$ ziran ui
Error: Could not connect to database at postgresql+asyncpg://localhost:5432/ziran
Check that PostgreSQL is running and ZIRAN_DATABASE_URL is configured correctly.
```
Exit code: 1

### Port Already in Use
```
$ ziran ui
Error: Port 8484 is already in use. Use --port to specify a different port.
```
Exit code: 1
