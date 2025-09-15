#!/bin/bash
# ProtoReveal Installation Script for ACSAC 2025 Artifact Evaluation

set -e  # Exit on any error

echo "=== ProtoReveal Installation Script ==="
echo "Installing dependencies and setting up the environment..."

# Update package lists
apt-get update

# Install system dependencies
apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    git \
    wget \
    curl \
    vim

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install --no-cache-dir -r requirements.txt

# Verify installation
echo "Verifying installation..."
python3 -c "import angr, cle, pyvex, pandas, sklearn; print('All dependencies installed successfully!')"

# Make scripts executable
chmod +x claims/*/run.sh

echo "=== Installation Complete ==="
echo "ProtoReveal is ready to use!"
echo ""
echo "To run the tool:"
echo "  python3 ./artifact/ProtoReveal/analysis.py <firmware_file> <architecture> <operation> <start_addr> <end_addr>"
echo ""
echo "Example:"
echo "  python3 ./artifact/ProtoReveal/analysis.py artifact/data/NUC230240/NUC240_ADC_Median_Filter.bin armcortexm predict 0x40000000 0x5FFFFFFF" 