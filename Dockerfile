# SecurityWatch Pro - Production Docker Image
FROM python:3.11-slim

# Set metadata
LABEL maintainer="SysAdmin Tools Pro <support@sysadmintoolspro.com>"
LABEL description="SecurityWatch Pro - Professional Security Monitoring System"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV FLASK_APP=securitywatch.web.app
ENV FLASK_ENV=production

# Create non-root user for security
RUN groupadd -r securitywatch && useradd -r -g securitywatch securitywatch

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/logs /app/reports /app/data && \
    chown -R securitywatch:securitywatch /app

# Create volume mount points
VOLUME ["/app/data", "/app/logs", "/app/reports", "/var/log"]

# Expose ports
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/stats || exit 1

# Switch to non-root user
USER securitywatch

# Default command - run web dashboard
CMD ["python", "web_server.py", "--host", "0.0.0.0", "--port", "5000"]
