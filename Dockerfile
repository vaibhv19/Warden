FROM python:3.12-slim

WORKDIR /app

# Install basic diagnostic tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy package files
COPY pyproject.toml .
COPY README.md .
COPY src/ ./src/

# Install the application in the container
RUN pip install --no-cache-dir .

# CLI entrypoint
ENTRYPOINT ["warden"]
CMD ["--help"]
