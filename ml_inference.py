"""
ml_inference.py

Core utilities for loading the trained UNSW-NB15 models and running
flat / hierarchical predictions, plus helpers for parsing Suricata / Zeek logs.

This file assumes the training notebook `ML_final_restructured.ipynb` has
already saved the following artifacts into a `models/` directory:

- rf_bin.joblib              (Model A: Benign vs Malicious)
- rf_dos_vs_other.joblib     (Model B: DoS vs Other attacks)
- rf_tri.joblib              (Model C: flat Benign/DoS/Other)
- bin_threshold.json         (deployment threshold for Model A)
- dos_threshold.json         (deployment threshold for Model B)
- features.json              (ordered list of feature names)
"""

from __future__ import annotations

import os
import json
from typing import Dict, Any

import numpy as np
import pandas as pd
import joblib

# Human-readable labels for the tri-class outputs
TRI_LABEL_NAMES = {
    0: "normal",        # Benign
    1: "dos",           # DoS (specific attack type)
    2: "other_attack",  # All other attack categories
}


  
# Helper: load feature list
  

def get_feature_list(art_dir: str = "models") -> list[str]:
    """Load the ordered list of feature names used by the models."""
    path = os.path.join(art_dir, "features.json")
    with open(path, "r", encoding="utf-8") as f:
        feats = json.load(f)
    return feats


 
# Load artifacts (same logic as in the notebook)
 

def load_flat_artifacts(art_dir: str = "models"):
    """
    Load artifacts required for *flat* predictions:
    - Model A (binary)
    - Model C (flat tri-class)
    - binary threshold
    - feature list
    """
    pipe_bin = joblib.load(os.path.join(art_dir, "rf_bin.joblib"))
    pipe_tri = joblib.load(os.path.join(art_dir, "rf_tri.joblib"))
    with open(os.path.join(art_dir, "bin_threshold.json"), "r", encoding="utf-8") as f:
        th = json.load(f)["threshold"]
    feats = get_feature_list(art_dir)
    return pipe_bin, pipe_tri, th, feats


def load_hier_artifacts(art_dir: str = "models") -> Dict[str, Any]:
    """
    Load artifacts required for *hierarchical* predictions (Model A → Model B).
    Returns a dict with:
      - pipe_bin: binary pipeline
      - pipe_dos: DoS vs Other pipeline
      - t1: binary threshold
      - t2: DoS threshold
      - feats: feature list
    """
    pipe_bin = joblib.load(os.path.join(art_dir, "rf_bin.joblib"))
    pipe_dos = joblib.load(os.path.join(art_dir, "rf_dos_vs_other.joblib"))
    with open(os.path.join(art_dir, "bin_threshold.json"), "r", encoding="utf-8") as f:
        t1 = json.load(f)["threshold"]
    with open(os.path.join(art_dir, "dos_threshold.json"), "r", encoding="utf-8") as f:
        t2 = json.load(f)["threshold"]
    feats = get_feature_list(art_dir)
    return dict(pipe_bin=pipe_bin, pipe_dos=pipe_dos, t1=t1, t2=t2, feats=feats)


# Backwards-compatible helper (αν κάτι παλιό καλεί αυτό)
def load_models_default(art_dir: str = "models"):
    """Return (model_bin, model_dos) for older scripts."""
    art = load_hier_artifacts(art_dir)
    return art["pipe_bin"], art["pipe_dos"]

 
#  Prediction functions (flat & hierarchical)
    

def predict_from_df(df_features: pd.DataFrame, mode: str = "both",
                    art_dir: str = "models") -> Dict[str, np.ndarray]:
    """
    Flat prediction using:
    - Model A (binary Benign vs Malicious)
    - Model C (flat tri-class Benign / DoS / Other)

    mode:
      - "binary": only Model A
      - "tri":    only Model C
      - "both":   both models
    """
    pipe_bin, pipe_tri, th, feats = load_flat_artifacts(art_dir)
    X = df_features[feats].copy()

    out: Dict[str, np.ndarray] = {}

    if mode in ("binary", "both"):
        scores = pipe_bin.predict_proba(X)[:, 1]
        out["binary_scores"] = scores
        out["binary_labels"] = (scores >= th).astype(int)

    if mode in ("tri", "both"):
        out["tri_labels"] = pipe_tri.predict(X)

    return out


def predict_hier_from_df(df_features: pd.DataFrame,
                         art_dir: str = "models") -> Dict[str, np.ndarray]:
    """
    Hierarchical prediction: Model A (binary) → Model B (DoS vs Other).
    Returns:
      - binary_scores: P(malicious)
      - binary_labels: 0/1
      - tri_labels:    0=normal, 1=DoS, 2=other_attack
    """
    art = load_hier_artifacts(art_dir)
    X = df_features[art["feats"]].copy()

    # Stage 1: binary
    s_bin = art["pipe_bin"].predict_proba(X)[:, 1]
    is_mal = s_bin >= art["t1"]

    tri = np.zeros(len(X), dtype=int)  # default: 0 (normal)
    if is_mal.any():
        s_dos = np.zeros(len(X))
        s_dos[is_mal] = art["pipe_dos"].predict_proba(X[is_mal])[:, 1]
        tri[is_mal] = (s_dos[is_mal] >= art["t2"]).astype(int) + 1  # 1=DoS, 2=Other

    return {
        "binary_scores": s_bin,
        "binary_labels": (s_bin >= art["t1"]).astype(int),
        "tri_labels": tri,
    }


def save_predictions_csv(df_features: pd.DataFrame,
                         out_csv: str,
                         mode: str = "hier",
                         art_dir: str = "models") -> pd.DataFrame:
    """
    Run predictions on df_features and save results to CSV.

    mode:
      - "flat": uses predict_from_df(mode="both")
      - "hier": uses predict_hier_from_df

    Returns the DataFrame that was written.
    """
    if mode == "flat":
        out = predict_from_df(df_features, mode="both", art_dir=art_dir)
    else:
        out = predict_hier_from_df(df_features, art_dir=art_dir)

    df_out = df_features.copy()

    if "binary_scores" in out:
        df_out["bin_prob_mal"] = out["binary_scores"]
        df_out["bin_label"] = out["binary_labels"]

    if "tri_labels" in out:
        df_out["tri_label"] = out["tri_labels"]
        df_out["final_label"] = df_out["tri_label"].map(TRI_LABEL_NAMES)

    df_out.to_csv(out_csv, index=False)
    return df_out


# Parsing helpers for Suricata EVE JSON and Zeek conn.log

def _ensure_types(df: pd.DataFrame, feature_list: list[str]) -> pd.DataFrame:
    """
    Ensure correct dtypes for the 7 features:

      - proto:   string
      - service: string
      - spkts, dpkts, sbytes, dbytes: int
      - dur:     float
    """
    df = df.copy()
    if "proto" in df.columns:
        df["proto"] = df["proto"].astype(str)
    if "service" in df.columns:
        df["service"] = df["service"].astype(str)
    for c in ("spkts", "dpkts", "sbytes", "dbytes"):
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(int)
    if "dur" in df.columns:
        df["dur"] = pd.to_numeric(df["dur"], errors="coerce").fillna(0.0).astype(float)

    return df[feature_list].copy()


def suricata_eve_to_features_df(eve_json_path: str,
                                art_dir: str = "models") -> pd.DataFrame:
    """
    Parse a Suricata EVE JSON log and return a DataFrame with the 7 features.

    Only `event_type == "flow"` events are used.
    """
    feats = get_feature_list(art_dir)
    rows = []

    with open(eve_json_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue

            if d.get("event_type") != "flow":
                continue

            flow = d.get("flow", {})
            proto = d.get("proto", "unknown")
            service = d.get("app_proto", "unknown") or "unknown"
            spkts = flow.get("pkts_toserver", 0)
            dpkts = flow.get("pkts_toclient", 0)
            sbytes = flow.get("bytes_toserver", 0)
            dbytes = flow.get("bytes_toclient", 0)
            dur = flow.get("duration", 0.0)

            rows.append([proto, service, spkts, dpkts, sbytes, dbytes, dur])

    df = pd.DataFrame(rows, columns=feats)
    return _ensure_types(df, feats)


def zeek_conn_to_features_df(conn_log_path: str,
                             art_dir: str = "models") -> pd.DataFrame:
    """
    Parse a Zeek conn.log (JSON per line) and return the features DataFrame.
    """
    feats = get_feature_list(art_dir)
    rows = []

    with open(conn_log_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue

            proto = d.get("proto", "unknown")
            service = d.get("service", "unknown") or "unknown"
            spkts = d.get("orig_pkts", 0)
            dpkts = d.get("resp_pkts", 0)
            sbytes = d.get("orig_bytes", 0)
            dbytes = d.get("resp_bytes", 0)
            dur = d.get("duration", 0.0)

            rows.append([proto, service, spkts, dpkts, sbytes, dbytes, dur])

    df = pd.DataFrame(rows, columns=feats)
    return _ensure_types(df, feats)
