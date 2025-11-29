````
# Network Security Analysis – ML + IDS Pipeline

This repository contains a **small but complete IDS-style pipeline** built on top of the **UNSW-NB15** dataset and **Suricata**.

We provide:

- A **hierarchical ML model**:
  - RandomForest #1: `normal` vs `attack`
  - RandomForest #2: for attack flows, `dos` vs `other_attack`
  - Final label ∈ {`normal`, `dos`, `other_attack`}
- **Offline batch classification** for UNSW-NB15-style CSV files
- A **FastAPI REST server** that exposes the trained model
- A script that **replays Suricata `eve.json` flow events** toward the REST API
- A helper script to **convert Suricata `eve.json` flow events to UNSW-style CSV features** (`eve_to_csv.py`)

The goal is to demonstrate **end-to-end integration**:

> `PCAP → Suricata → eve.json → (REST API or CSV) → ML predictions`

---

## 1. Environment & Requirements

### 1.1 Python version

The project is developed and tested with:

- **Python 3.11**

You should use Python 3.11.x for full compatibility (especially with the trained scikit-learn models).

### 1.2 Virtual environment setup (Windows / PowerShell)

From the project root:

```powershell
cd C:\PROJECT_ROOT

# Create venv (only once)
python -m venv unswenv

# Activate venv
.\unswenv\Scripts\activate
````

Your prompt should look like:

```text
(unswenv) PS C:\PROJECT_ROOT>
```

### 1.3 Install dependencies

With the virtualenv activated:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 2. Repository structure

```text
PROJECT_ROOT/
  classify_flows.py          # Offline UNSW CSV classification (normal / dos / other_attack)
  ml_inference.py            # Shared code to load models and run hierarchical predictions
  rest_server.py             # FastAPI app exposing /predict_one
  eve_to_rest.py             # Replay Suricata eve.json flows to the REST API
  eve_to_csv.py              # Convert Suricata eve.json flows to UNSW-style CSV features

  models/
    rf_bin.joblib            # RandomForest model: normal vs attack
    rf_dos_vs_other.joblib   # RandomForest model: dos vs other_attack

  data/
    UNSW_NB15_training-set.csv
    UNSW_NB15_testing-set.csv
    suricata_flows_pcap1.csv # Example CSV generated from eve_to_csv.py

  logs/
    pcap1/
      eve.json               # Suricata output generated from PCAP or live capture

  out/
    testing_predictions.csv  # Example offline classification output

  README.md
  requirements.txt
```

---

## 3. Hierarchical ML model – Overview

The prediction logic is implemented in `ml_inference.py` and used by both the CLI and REST server.

### 3.1 Binary classifier (`rf_bin.joblib`)

* **Input**: a flow with selected features (7-feature subset of UNSW-NB15)
* **Output**: `normal` or `attack`

### 3.2 DoS vs Other classifier (`rf_dos_vs_other.joblib`)

* Only used if the binary classifier predicted `attack`
* **Output**: `dos` or `other_attack`

### 3.3 Final label logic

* If binary label = `normal` → final label = `normal`
* If binary label = `attack` and second model = `dos` → final label = `dos`
* If binary label = `attack` and second model = `other_attack` → final label = `other_attack`

This allows us to:

* Detect whether there is an attack, and
* Highlight specifically **DoS attacks**, which are often operationally important.

---

## 4. Offline classification – UNSW CSV → Predictions CSV

**Script**: `classify_flows.py`

This is the batch mode, mainly for evaluation / analysis.

### 4.1 Command

From `PROJECT_ROOT`:

```bash
python classify_flows.py ^
    --data data\UNSW_NB15_testing-set.csv ^
    --out  out\testing_predictions.csv
```

**Arguments:**

* `--data` : path to input CSV with flows (UNSW-NB15-style features)
* `--out`  : path to output CSV that will contain predictions

### 4.2 What the script does

The script:

1. Loads models from `models/`:

   * `models/rf_bin.joblib`
   * `models/rf_dos_vs_other.joblib`
2. Reads the CSV from `--data` into a pandas DataFrame.
3. Applies the same preprocessing and feature selection as during training (via the stored pipelines inside the joblib models).
4. For each row (flow):

   * Predicts `normal` vs `attack`
   * If `attack`, also predicts `dos` vs `other_attack`
   * Produces `final_label` ∈ {`normal`, `dos`, `other_attack`}
5. Writes everything to `--out`.

The output CSV typically includes:

* The original feature columns used by the model
* The intermediate labels:

  * `y_bin` (binary output: `normal` / `attack`)
  * `y_dos` (for attack flows: `dos` / `other_attack`)
* The final combined label:

  * `final_label` ∈ {`normal`, `dos`, `other_attack`}

At the end, the script prints for convenience something like:

```text
[SUMMARY] Final label distribution:
final_label
dos             57623
normal          24692
other_attack       17
Name: count, dtype: int64
```

### 4.3 From eve.json to UNSW-style CSV (`eve_to_csv.py`)

Sometimes you want to:

* Run Suricata on a PCAP or live traffic,
* Take the resulting `eve.json` flow logs,
* And **feed them into the same ML pipeline as UNSW-NB15**.

For this, use **`eve_to_csv.py`**.

**Script**: `eve_to_csv.py`

**Input**: Suricata `eve.json` (with `event_type = "flow"`)
**Output**: CSV with UNSW-like feature columns:

* `proto`
* `service`
* `spkts`
* `dpkts`
* `sbytes`
* `dbytes`
* `dur`

#### 4.3.1 Command

From `PROJECT_ROOT`:

```bash
python eve_to_csv.py ^
    --eve logs\pcap1\eve.json ^
    --out data\suricata_flows_pcap1.csv
```

**Arguments:**

* `--eve` / `-e` : path to `eve.json` generated by Suricata
* `--out` / `-o` : output CSV path for features (e.g. `data/suricata_flows_pcap1.csv`)

If no flow events are found, the script will raise an error to let you know.

Internally it:

1. Reads `eve.json` line by line.
2. Keeps only entries with `event_type = "flow"`.
3. Extracts:

   * `proto` (from top-level `proto`)
   * `service` (from `app_proto`)
   * `spkts`, `dpkts`, `sbytes`, `dbytes`, `dur` (from the `flow` object)
4. Builds a pandas DataFrame with well-defined dtypes.
5. Writes the result to CSV and prints a small summary, e.g.:

```text
[OK] Wrote 1234 flows to: data/suricata_flows_pcap1.csv
[OK] Columns: proto, service, spkts, dpkts, sbytes, dbytes, dur
```

You can then plug this CSV directly into `classify_flows.py`, for example:

```bash
python classify_flows.py ^
    --data data\suricata_flows_pcap1.csv ^
    --out  out\suricata_flows_pcap1_predictions.csv
```

---

## 5. Suricata integration – REST-based IDS-style pipeline

In online / IDS-style mode, we rely on Suricata to process network traffic and emit `eve.json` logs, then pass the flows to our model via HTTP.

### 5.1 Step 1 – Generate `eve.json` with Suricata

Suricata command example (PCAP replay):

```bash
suricata -r /path/to/pcap1.pcap \
  -c /etc/suricata/suricata.yaml \
  -l C:\PROJECT_ROOT\logs\pcap1
```

This produces an `eve.json` file under `logs\pcap1\` that contains Suricata events, including flow entries.

The pipeline is similar if Suricata is run live – as long as it writes an `eve.json` file.

### 5.2 Step 2 – Start the REST server (FastAPI + Uvicorn)

**Script**: `rest_server.py`

From `PROJECT_ROOT` (with venv active):

```bash
uvicorn rest_server:app --reload --port 8000
```

The server listens on: `http://127.0.0.1:8000`

**Exposed endpoints:**

* `GET /health` – simple health check
* `POST /predict_one` – classify a single flow

#### 5.2.1 REST API contract

**Request – `POST /predict_one`**

Example JSON body (one flow, 7 features):

```json
{
  "dur": 0.15,
  "spkts": 12,
  "dpkts": 9,
  "sbytes": 8500,
  "dbytes": 900,
  "proto": "tcp",
  "state": "EST"
}
```

**Response – example:**

```json
{
  "binary_label": "attack",
  "dos_vs_other": "dos",
  "final_label": "dos"
}
```

**Fields:**

* `binary_label` – output of the normal vs attack model
* `dos_vs_other` – output of the DoS vs other_attack model
  (only meaningful when `binary_label == "attack"`)
* `final_label` – combined label:

  * `normal`
  * `dos`
  * `other_attack`

Example `curl` call:

```bash
curl -X POST "http://127.0.0.1:8000/predict_one" \
  -H "Content-Type: application/json" \
  -d '{
        "dur": 0.15,
        "spkts": 12,
        "dpkts": 9,
        "sbytes": 8500,
        "dbytes": 900,
        "proto": "tcp",
        "state": "EST"
      }'
```

### 5.3 Step 3 – Replay Suricata flows to the REST API

**Script**: `eve_to_rest.py`

From another terminal (while the REST server is running):

```bash
python eve_to_rest.py ^
    --eve C:\PROJECT_ROOT\logs\pcap1\eve.json ^
    --url http://127.0.0.1:8000 ^
    --limit 1000
```

**Arguments:**

* `--eve`   : path to Suricata `eve.json`
* `--url`   : base URL of the REST server (e.g. `http://127.0.0.1:8000`)
* `--limit` : maximum number of flow events to send (optional; if omitted, a default is used)

**What it does:**

* Reads `eve.json` line by line.
* Selects entries of type `flow`.
* For each flow:

  * Extracts the 7 features required by the model (duration, packets/bytes, protocol, state, etc.).
  * Builds the JSON request body for `/predict_one`.
  * Sends an HTTP POST to the REST API.
  * Collects the returned `final_label` for each successfully processed flow.
* At the end, prints a summary, for example:

```text
[SUMMARY] REST predictions:
normal:       800
dos:          150
other_attack: 50
```

---

## 6. Putting it all together

We now have **two usage modes**, plus a helper conversion step:

### 6.1 Offline evaluation (dataset-centric)

**Input:**

* UNSW-NB15 CSV files
* Or CSVs generated from Suricata `eve.json` via `eve_to_csv.py`

**Tools:**

* `eve_to_csv.py` (optional, if starting from `eve.json`)
* `classify_flows.py`

**Output:**

* Predictions CSV with `final_label`
* Summary distribution of `normal`, `dos`, `other_attack`

### 6.2 IDS-style integration (Suricata-centric, REST)

**Input:**

* PCAP or live traffic, processed by Suricata into `eve.json`

**Tools:**

* Suricata → produces `logs/.../eve.json`
* `rest_server.py` → FastAPI + Uvicorn exposing `/predict_one`
* `eve_to_rest.py` → replays flows to the REST endpoint

**Output:**

* Live / batch predictions for each flow, including:

  * Binary decision (`normal` vs `attack`)
  * DoS vs other
  * Final label (`normal`, `dos`, `other_attack`)
* Simple counters of how many flows fall into each category

This gives a complete pipeline that shows:

* A trained ML model based on **UNSW-NB15**
* A clean Python inference layer
* A REST interface suitable for integration with GUI, Suricata wrappers, or other services
* A practical workflow from raw traffic (PCAP/live) or logs (`eve.json`) to **security-relevant labels**

```
```
