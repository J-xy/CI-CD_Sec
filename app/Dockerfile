# -- BUILD STAGE --
FROM python:3.9-slim AS builder

# Create a virtual environment to keep dependencies neatly isolated for copying
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# -- RUNTIME STAGE --
FROM python:3.9-slim

# Create a non-root user with an explicitly high UID
# High UIDs prevent accidental overlap with host OS system users
RUN useradd -m -u 10001 appuser

# Copy only the compiled virtual environment from the builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory and copy application code
WORKDIR /app
COPY --chown=appuser:appuser . /app

# Switch to the non-root user BEFORE defining the entrypoint
USER 10001

# Healthcheck without relying on curl being installed in the OS
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

EXPOSE 5000
CMD ["python", "app.py"]