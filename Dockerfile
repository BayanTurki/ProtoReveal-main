# ProtoReveal Docker Container for ACSAC 2025 Artifact Evaluation
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    git \
    wget \
    curl \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Install gdown for model download
RUN pip3 install gdown

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the entire ProtoReveal codebase
COPY . .

# Make scripts executable
RUN chmod +x install.sh

# Set Python path
ENV PYTHONPATH=/app

# Default command
CMD ["/bin/bash"]
