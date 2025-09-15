#!/bin/bash
# Download ML models for ProtoReveal
# This script downloads the required ML models from Google Drive

set -e

echo "=== ProtoReveal Model Download ==="
echo "Downloading ML models required for prediction..."

# Create models directory if it doesn't exist
mkdir -p artifact/ProtoReveal

# Download predictor.pt (286 MB)
echo "Downloading predictor.pt..."
gdown 1a5RdhCNvRFBgp9cJAjXggrC-Rr7xhbx2 -O artifact/ProtoReveal/predictor.pt

# Download random_forest_model.pt (255 MB)  
echo "Downloading random_forest_model.pt..."
gdown 18uyO3lZ8Z8mAsYmhObMEYtBm0BZ4cog1 -O artifact/ProtoReveal/random_forest_model.pt

echo "=== Model download complete! ==="
echo "Models are now available in artifact/ProtoReveal/"
ls -la artifact/ProtoReveal/*.pt
