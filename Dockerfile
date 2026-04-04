FROM python:3.12-slim

WORKDIR /app

# Install system deps (curl for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Data directory for SQLite databases
RUN mkdir -p /app/data

# Default — overridden per-service in docker-compose.yml
CMD ["uvicorn", "mcp_oauth_server.main:app", "--host", "0.0.0.0", "--port", "8080"]
