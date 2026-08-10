# Offline-friendly image: default CMD is dry-run (no credentials required).
FROM python:3.12-slim

WORKDIR /app

# System deps for matplotlib
RUN apt-get update && apt-get install -y --no-install-recommends \
    libfreetype6 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY policies ./policies
COPY examples ./examples

RUN pip install --no-cache-dir -e .

ENV AWSTOOLS_OFFLINE=1 \
    MPLBACKEND=Agg \
    PYTHONUNBUFFERED=1

# Health: offline cost analysis produces a report
HEALTHCHECK --interval=30s --timeout=15s --start-period=20s --retries=2 \
  CMD python -m awstools cost --offline --output-dir /tmp/hc --no-export-actions --quiet || exit 1

ENTRYPOINT ["python", "-m", "awstools"]
CMD ["cost", "--offline", "--output-dir", "/tmp/awstools-out", "--quiet"]
