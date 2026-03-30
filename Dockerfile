# ── VulnScanner AI — Docker Image ─────────────────────────────────────────────
# Multi-stage build: keeps the final image lean

# Stage 1: builder
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: runtime
FROM python:3.11-slim AS runtime

LABEL maintainer="VulnScanner AI Contributors"
LABEL description="ML-powered OWASP Top 10 vulnerability scanner"
LABEL version="1.0.0"

# Runtime system deps (weasyprint needs these)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf2.0-0 \
    libffi-dev libcairo2 git \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy project files
COPY vulnscanner/ ./vulnscanner/
COPY rules/ ./rules/
COPY templates/ ./templates/
COPY models/ ./models/
COPY pyproject.toml .

# Install the package itself (editable-style)
RUN pip install --no-cache-dir -e . --no-deps

# Create non-root user for security
RUN useradd -m -u 1000 scanner
RUN mkdir -p /reports && chown scanner:scanner /reports
USER scanner

VOLUME ["/scan-target", "/reports"]

ENTRYPOINT ["vulnscanner"]
CMD ["--help"]
