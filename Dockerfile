# =============================================================================
# AZSploitMapper Docker Image
# =============================================================================
# Multi-stage build for a minimal, secure production image.
#
# Security features:
# - Runs as non-root user (appuser, UID 1000)
# - Minimal attack surface (no curl, no shell tools beyond Python)
# - TLS certificates mounted at runtime via volume
# - No Azure CLI installed (uses Service Principal via SDK only)
# - Separate build stage to exclude dev tools from final image
# =============================================================================

# --- Stage 1: Build dependencies ---
FROM python:3.11-slim AS builder

WORKDIR /build

# Install only the Python packages needed
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# --- Stage 2: Production image ---
FROM python:3.11-slim

# Security: create a non-root user
RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid 1000 --create-home appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy only the application code (not venv, tests, terraform, etc.)
COPY azsploitmapper/ /app/azsploitmapper/
COPY config/ /app/config/

# Create directories for runtime data with correct ownership
RUN mkdir -p /app/data /app/logs /app/certs && \
    chown -R appuser:appuser /app

# Security: switch to non-root user
USER appuser

# Expose HTTPS port (not 8080 -- we use TLS on 8443)
EXPOSE 8443

# Health check using Python instead of curl (curl not installed)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('https://localhost:8443/api/health', context=__import__('ssl')._create_unverified_context())"]

# Run the web dashboard with TLS
CMD ["python", "-m", "azsploitmapper", "serve", "--port", "8443"]
