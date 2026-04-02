FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . /app

# Add main workspace to PYTHONPATH to allow imports across modules (e.g. backend and sandbox)
ENV PYTHONPATH=/workspace
WORKDIR /workspace/backend

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
