# Docker Infrastructure

## Platform: Docker
**Primary public infrastructure for ACSAC 2025 Artifacts Evaluation**

> **Note**: For complete instructions with all installation options, see `README.txt`. This file provides Docker-specific details only.

## Quick Start

### 1. Clone and navigate to repository
```bash
git clone https://github.com/BayanTurki/ProtoReveal-main.git
cd ProtoReveal-main
```

### 2. Start the container
```bash
docker-compose up --build -d
```

### 3. Download ML models (REQUIRED FIRST)
```bash
# Download models from Google Drive
docker exec -it protoreveal-ae /app/download_models.sh
```

### 4. Execute analysis commands
```bash
# Analysis command
# Note: angr warnings are normal and expected - just wait for results
python3 ./artifact/ProtoReveal/analysis.py artifact/data/NUC230240/NUC240_ADC_Median_Filter.bin armcortexm predict 0x40000000 0x5FFFFFFF

# Test command
python3 ./artifact/ProtoReveal/test.py LoadFuncToSRAM.bin test

# Prediction command
python3 ./artifact/ProtoReveal/train/Predict_.py
```

### 5. Copy output files
```bash
# Copy output files from container to host
docker cp protoreveal-ae:/app/prediction.csv .
docker cp protoreveal-ae:/app/prediction.json .
docker cp protoreveal-ae:/app/Level3_PrePredict.csv .
docker cp protoreveal-ae:/app/New_Level3_depth.csv .
docker cp protoreveal-ae:/app/Result_1.csv .
```

### 6. Stop the container
```bash
docker-compose down
```

## Expected Output Files
- `prediction.csv` and `prediction.json` (from analysis command)
- `New_Level3_depth.csv` (from test command)
- `Result_1.csv` (from prediction command)
- `Level3_PrePredict.csv` (from analysis command)

## Model Download

The ML models are too large for GitHub (>100MB). Download them manually:

1. **predictor.pt** (286 MB): [Download from Google Drive](https://drive.google.com/file/d/1a5RdhCNvRFBgp9cJAjXggrC-Rr7xhbx2/view?usp=sharing)
2. **random_forest_model.pt** (255 MB): [Download from Google Drive](https://drive.google.com/file/d/18uyO3lZ8Z8mAsYmhObMEYtBm0BZ4cog1/view?usp=sharing)

Place both files in `artifact/ProtoReveal/` directory.


## Troubleshooting
- Ensure Docker is installed and running
- Verify that model files (predictor.pt, random_forest_model.pt) are in artifact/ProtoReveal/
