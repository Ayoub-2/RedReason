FROM python:3.9-slim

WORKDIR /app

# Install system dependencies (needed for some impacket/crypto libs)
RUN apt-get update && apt-get install -y \
    gcc \
    libkrb5-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Create reports directory
RUN mkdir -p reports

ENTRYPOINT ["python", "main.py"]
