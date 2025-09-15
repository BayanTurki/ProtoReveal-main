ProtoReveal: Recovering Peripheral Maps and Protocols to Expedite Firmware Reverse Engineering
==============================================================================================

OVERVIEW
--------
ProtoReveal is a static analysis tool that automatically identifies peripheral access patterns and predicts communication protocols in firmware binaries to expedite reverse engineering. 

ARTIFACT CONTENTS
-----------------
- artifact/            : Main code, models, and data
  - ProtoReveal/       : Main source code directory
    - analysis.py      : Core analysis script
    - test.py         : Batch testing script
    - features.py     : Feature extraction module
    - graph.py        : Control flow graph analysis
    - predict/        : Machine learning prediction modules
  - data/             : Sample firmware dataset
- infrastructure/      : Docker infrastructure information
- claims/             : Reproducibility claims and tests
- requirements.txt    : Python dependencies
- install.sh         : One-click installation script
- Dockerfile         : Docker container definition


INSTALLATION
------------

### Option 1: Docker Compose (recommended)

```bash
# Clone the repository
git clone https://github.com/BayanTurki/ProtoReveal-main.git
cd ProtoReveal-main

# Start the container
docker-compose up --build -d

# Download ML models (required for prediction)
# Models: 
# - predictor.pt (286MB): https://drive.google.com/file/d/1a5RdhCNvRFBgp9cJAjXggrC-Rr7xhbx2/view?usp=sharing
# - random_forest_model.pt (255MB): https://drive.google.com/file/d/18uyO3lZ8Z8mAsYmhObMEYtBm0BZ4cog1/view?usp=sharing
docker exec -it protoreveal-ae /app/download_models.sh

# 1. Run analysis command + save output
# Note: angr warnings are normal and expected - just wait for results
docker exec -it protoreveal-ae python3 ./artifact/ProtoReveal/analysis.py artifact/data/NUC230240/NUC240_ADC_Median_Filter.bin armcortexm predict 0x40000000 0x5FFFFFFF
docker cp protoreveal-ae:/app/prediction.csv .
docker cp protoreveal-ae:/app/prediction.json .

# 2. Run test + prediction command + save output
docker exec -it protoreveal-ae bash -c "python3 ./artifact/ProtoReveal/test.py LoadFuncToSRAM.bin test && python3 ./artifact/ProtoReveal/train/Predict_.py"
docker cp protoreveal-ae:/app/New_Level3_depth.csv .
docker cp protoreveal-ae:/app/Result_1.csv .

# Stop the container
docker-compose down
```

**Expected output files:**
- `prediction.csv` - Analysis results with protocol predictions
- `prediction.json` - JSON format of analysis results  
- `New_Level3_depth.csv` - Generated from test command
- `Result_1.csv` - Generated from prediction command
- `Level3_PrePredict.csv` - Generated from analysis command



### Option 2: Native Installation (Linux)

```bash
# Step 1: Clone the repository
git clone https://github.com/BayanTurki/ProtoReveal-main.git
cd ProtoReveal-main

# Step 2: Make script executable
chmod +x install.sh

# Step 3: Run installation (requires sudo)
sudo ./install.sh

# Step 4: Verify installation
python3 -c "import angr, cle, pyvex, pandas, sklearn; print('All dependencies installed successfully!')"

# Step 5: Download ML models (required for prediction)
# Models: 
# - predictor.pt (286MB): https://drive.google.com/file/d/1a5RdhCNvRFBgp9cJAjXggrC-Rr7xhbx2/view?usp=sharing
# - random_forest_model.pt (255MB): https://drive.google.com/file/d/18uyO3lZ8Z8mAsYmhObMEYtBm0BZ4cog1/view?usp=sharing
./download_models.sh

# Step 6: Run analysis command
# Note: angr warnings are normal and expected - just wait for results
python3 ./artifact/ProtoReveal/analysis.py artifact/data/NUC230240/NUC240_ADC_Median_Filter.bin armcortexm predict 0x40000000 0x5FFFFFFF

# Step 7: Run test command
python3 ./artifact/ProtoReveal/test.py LoadFuncToSRAM.bin test

# Step 8: Run prediction command
python3 ./artifact/ProtoReveal/train/Predict_.py

# Step 9: Check output files
ls -la *.csv *.json
```

**Expected output files:**
- `prediction.csv` and `prediction.json` (from analysis command)
- `New_Level3_depth.csv` (from test command)
- `Result_1.csv` (from prediction command)

**❌ This will NOT work on macOS or Windows!** For macOS/Windows, use Docker Compose (Option 1) or Cross-Platform Installation (Option 3).





### Option 3: Cross-Platform Installation (macOS/Windows/Linux)

**For users who want to install dependencies directly without Docker:**

```bash
# Step 1: Clone the repository
git clone https://github.com/BayanTurki/ProtoReveal-main.git
cd ProtoReveal-main

# Step 2: Install Python 3.9+ (if not already installed)
# macOS: brew install python3
# Windows: Download from python.org
# Linux: sudo apt-get install python3 python3-pip

# Step 3: Install Python dependencies
pip3 install -r requirements.txt

# Step 4: Verify installation
python3 -c "import angr, cle, pyvex, pandas, sklearn; print('All dependencies installed successfully!')"

# Step 5: Download ML models (required for prediction)
# Models: 
# - predictor.pt (286MB): https://drive.google.com/file/d/1a5RdhCNvRFBgp9cJAjXggrC-Rr7xhbx2/view?usp=sharing
# - random_forest_model.pt (255MB): https://drive.google.com/file/d/18uyO3lZ8Z8mAsYmhObMEYtBm0BZ4cog1/view?usp=sharing
./download_models.sh

# Step 6: Run analysis command
python3 ./artifact/ProtoReveal/analysis.py artifact/data/NUC230240/NUC240_ADC_Median_Filter.bin armcortexm predict 0x40000000 0x5FFFFFFF

# Step 7: Run test command
python3 ./artifact/ProtoReveal/test.py LoadFuncToSRAM.bin test

# Step 8: Run prediction command
python3 ./artifact/ProtoReveal/train/Predict_.py

# Step 9: Check output files
ls -la *.csv *.json
```

**Expected output files:**
- `prediction.csv` and `prediction.json` (from analysis command)
- `New_Level3_depth.csv` (from test command)
- `Result_1.csv` (from prediction command)

USAGE
-----

### Analysis Command
To analyze one entire firmware binary:
python3 ./artifact/ProtoReveal/analysis.py <path-to-firmware> <architecture> predict <start-address> <end-address>

Example:
python3 ./artifact/ProtoReveal/analysis.py artifact/data/NUC230240/NUC240_ADC_Median_Filter.bin armcortexm predict 0x40000000 0x5FFFFFFF

### Test Command
To analyze firmware with ground truth extraction:
python3 ./artifact/ProtoReveal/test.py <FW-name> test

Example:
python3 ./artifact/ProtoReveal/test.py LoadFuncToSRAM.bin test


### Prediction Command
To make predictions using pre-trained models:
python3 ./artifact/ProtoReveal/train/Predict_.py

OUTPUT
------
The tool generates:
- prediction.csv      : ML predictions (from analysis command)
- prediction.json     : Results summary (from analysis command)
- Level3_PrePredict.csv: Feature matrix (from analysis command)
- New_Level3_depth.csv: Test analysis results (from test command)
- Result_1.csv        : Final predictions (from prediction command)

REPRODUCIBILITY CLAIMS
----------------------
See claims/ directory for specific reproducibility experiments.

LICENSE
-------
See license.txt for licensing information.

CONTACT
-------
For questions about this artifact, contact the authors.
Email: Turkistani.3@buckeyemail.osu.edu

LIMITATIONS
-----------
- Requires ARM Cortex-M firmware binaries
- Some complex firmware may produce minimal results
- Analysis time varies by firmware complexity
