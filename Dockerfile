# Stage 1: Build frontend
FROM node:20-slim AS frontend-builder
WORKDIR /app/ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

# Stage 2: Python runtime
FROM python:3.12-slim AS runtime
WORKDIR /app
# Install system deps for asyncpg
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml uv.lock hatch_build.py ./
COPY ziran/ ./ziran/
COPY --from=frontend-builder /app/ui/dist/ ./ziran/interfaces/web/static/
# Install using pip (no uv in container for simplicity)
RUN pip install --no-cache-dir ".[ui]"
EXPOSE 8484
ENV ZIRAN_DATABASE_URL=postgresql+asyncpg://postgres:postgres@db:5432/ziran
CMD ["ziran", "ui", "--host", "0.0.0.0"]
