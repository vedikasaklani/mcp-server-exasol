# Use a slim Python base image
FROM python:3.12-slim

# Install system dependencies + semgrep via apt (avoids pip dependency conflicts)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        git \
        build-essential \
        libpq-dev \
        python3-dev \
    && rm -rf /var/lib/apt/lists/*
    
#semgrep is downloaded in venv as it has differernt mcp version dependency than fastmcp
RUN python -m venv /opt/semgrep-venv && \
    /opt/semgrep-venv/bin/pip install --no-cache-dir semgrep==1.176.1

# Make the semgrep binary discoverable without polluting the app's venv
ENV SEMGREP_BIN=/opt/semgrep-venv/bin/semgrep

# Set working directory
WORKDIR /app

# Copy requirements first (better layer caching)
COPY requirements.txt .

# Install the app's own Python dependencies in the default environment
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 8000

# Health check 
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/ || exit 1

# Run the application
CMD uvicorn service_management.api.api:app --host 0.0.0.0 --port ${PORT:-8000}