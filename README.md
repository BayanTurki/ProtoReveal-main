# ProtoReveal


## Overview
ProtoReveal is a static analysis tool that automatically identifies peripheral access patterns and predicts communication protocols in firmware binaries to expedite reverse engineering.  

---

## Setup

Tested on Python 3.8 for Debian/Ubuntu.

```bash
pip install -Ur requirements.txt
```

## Pretrained Models

Download the models into the `ProtoReveal/` directory:

* [predictor.pt](https://drive.google.com/file/d/1a5RdhCNvRFBgp9cJAjXggrC-Rr7xhbx2/view?usp=sharing) (286 MB)
* [random_forest_model.pt](https://drive.google.com/file/d/18uyO3lZ8Z8mAsYmhObMEYtBm0BZ4cog1/view?usp=sharing) (255 MB)

## Usage

### Analysis Command

To analyze one entire firmware binary, use the following command:

```bash
./ProtoReveal/analysis.py <path-to-firmware> <architecture> predict <start-address> <end-address>
```

For example:

```bash
./ProtoReveal/analysis.py data/NUC230240/NUC240_ADC_Median_Filter.bin armcortexm predict 0x40000000 0x5FFFFFFF
```

The results will be written to `prediction.csv` and `prediction.json`.

### Test Command

To analyze the firmware, use the following command:

```bash
./ProtoReveal/test.py <FW-name> test
```

For example:

```bash
./ProtoReveal/test.py LoadFuncToSRAM.bin.bin test
```

This command will analyze the specified firmware by extracting all the access chains along with 
the ground truth, generating the result in `New_Level3_depth.csv`.

### Prediction Command

To make predictions, use the following command:

```bash
./ProtoReveal/train/Predict_.py
```

This command will perform the prediction and generate the file `Result_1.csv`.
