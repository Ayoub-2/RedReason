FROM python:3.9.18-slim

WORKDIR /app

# Install system dependencies (needed for some impacket/crypto libs)
RUN apt-get update && apt-get install -y \
    gcc \
    libkrb5-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 redreason

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code with proper ownership
COPY --chown=redreason:redreason . .

# Create reports directory with proper permissions
RUN mkdir -p reports && chown -R redreason:redreason /app

# Switch to non-root user
USER redreason

ENTRYPOINT ["python", "main.py"]
