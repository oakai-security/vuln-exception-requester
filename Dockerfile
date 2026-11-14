# Multi-stage non-root container for vuln-exception-requester
FROM python:3.12-slim-bookworm AS builder

WORKDIR /app
RUN pip install --no-cache-dir uv

COPY pyproject.toml README.md /app/
RUN uv venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

COPY src /app/src
RUN uv pip install --no-cache-dir .

# Runtime stage
FROM python:3.12-slim-bookworm AS runtime

# Install git for repository updates
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root user (UID 1003) in group oakai (GID 2000)
RUN groupadd -g 2000 oakai && \
    useradd -u 1003 -g oakai -s /bin/false -m vuln-req

WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV UDS_REQUEST_SOCKET="/run/oakai/request.sock"
ENV UDS_APPROVE_SOCKET="/run/oakai/approve.sock"
ENV VULN_REGISTER_PATH="/repo"

# Pre-create socket directory with permissions
RUN mkdir -p /run/oakai && chown -R vuln-req:oakai /run/oakai && chmod 770 /run/oakai

USER vuln-req:oakai

EXPOSE 0
ENTRYPOINT ["vuln-exception-requester"]
CMD ["serve"]
