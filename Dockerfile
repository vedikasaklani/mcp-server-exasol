# Use a slim Python base image
FROM python:3.11-slim

# Install system dependencies + semgrep via apt (avoids pip dependency conflicts)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        git \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install semgrep via pip in an isolated way (pinned version, no conflicts)
RUN pip install --no-cache-dir semgrep==1.45.0

# Set working directory
WORKDIR /app

# Copy requirements first (better layer caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 8000

# Health check 
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/ || exit 1

# Run the application
CMD uvicorn server_management.api.api:app --host 0.0.0.0 --port ${PORT:-8000}
