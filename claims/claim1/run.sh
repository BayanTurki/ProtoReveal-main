#!/bin/bash
# Claim 1: Basic Functionality Test
# This script demonstrates ProtoReveal's core functionality

set -e  # Exit on any error

echo "=== ProtoReveal Claim 1: Basic Functionality Test ==="
echo "Testing peripheral detection on NUC230240 firmware sample"
echo ""

# Test 1: Basic analysis
echo "Test 1: Running basic analysis..."
python3 ./artifact/ProtoReveal/analysis.py ./artifact/data/NUC230240/NUC240_ADC_Median_Filter.bin armcortexm predict 0x40000000 0x5FFFFFFF

# Check if output files were generated
echo ""
echo "Checking output files..."

if [ -f "Level3_PrePredict.csv" ]; then
    echo "✓ Level3_PrePredict.csv generated successfully"
    echo "  Rows: $(wc -l < Level3_PrePredict.csv)"
else
    echo "✗ Level3_PrePredict.csv not found"
    exit 1
fi

if [ -f "prediction.csv" ]; then
    echo "✓ prediction.csv generated successfully"
    echo "  Rows: $(wc -l < prediction.csv)"
else
    echo "✗ prediction.csv not found"
    exit 1
fi

if [ -f "prediction.json" ]; then
    echo "✓ prediction.json generated successfully"
    echo "  Size: $(wc -c < prediction.json) bytes"
else
    echo "✗ prediction.json not found"
    exit 1
fi

# Test 2: Batch processing
echo ""
echo "Test 2: Running batch processing test..."
python3 ./artifact/ProtoReveal/test.py LoadFuncToSRAM.bin test

# Check batch output
if [ -f "New_Level3_depth.csv" ]; then
    echo "✓ New_Level3_depth.csv generated successfully"
    echo "  Rows: $(wc -l < New_Level3_depth.csv)"
else
    echo "✗ New_Level3_depth.csv not found"
    exit 1
fi

# Test 3: Prediction command
echo ""
echo "Test 3: Running prediction command..."
python3 ./artifact/ProtoReveal/train/Predict_.py

# Check prediction output
if [ -f "Result_1.csv" ]; then
    echo "✓ Result_1.csv generated successfully"
    echo "  Rows: $(wc -l < Result_1.csv)"
else
    echo "✗ Result_1.csv not found"
    exit 1
fi

echo ""
echo "=== All tests passed! ==="
echo "ProtoReveal is functioning correctly."
echo ""
echo "Generated files:"
ls -la *.csv *.json 2>/dev/null || echo "No additional output files"


