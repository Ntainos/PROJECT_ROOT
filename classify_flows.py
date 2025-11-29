"""
classify_flows.py

CLI tool to run the trained UNSW-NB15 models on:
  - a CSV file with UNSW-NB15 flows
  - a Suricata EVE JSON log
  - a Zeek conn.log (JSON per line)

By default it uses the hierarchical model:
  normal / dos / other_attack
"""

import argparse
import os

import pandas as pd

from ml_inference import (
    get_feature_list,
    save_predictions_csv,
    suricata_eve_to_features_df,
    zeek_conn_to_features_df,
)


def load_features_from_csv(csv_path: str, art_dir: str = "models") -> pd.DataFrame:
    feats = get_feature_list(art_dir)
    df_raw = pd.read_csv(csv_path)
    missing = [c for c in feats if c not in df_raw.columns]
    if missing:
        raise ValueError(
            f"Missing required feature columns in {csv_path}: {missing}"
        )
    return df_raw[feats].copy()


def main():
    parser = argparse.ArgumentParser(
        description="Classify flows using the trained UNSW-NB15 models."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--data", help="CSV file (e.g. UNSW_NB15_testing-set.csv)")
    group.add_argument("--eve", help="Suricata EVE JSON log")
    group.add_argument("--zeek", help="Zeek conn.log (JSON per line)")

    parser.add_argument(
        "--mode",
        choices=["hier", "flat"],
        default="hier",
        help="Prediction mode: 'hier' (normal/dos/other) or 'flat'.",
    )
    parser.add_argument(
        "--models", default="models",
        help="Directory with joblib models and JSON artifacts (default: models)",
    )
    parser.add_argument(
        "--out", required=True,
        help="Output CSV path for predictions.",
    )

    args = parser.parse_args()

    print(f"[INFO] Using models from: {args.models}")

    # ------------------------------------------------------------------ load
    if args.data:
        print(f"[INFO] Loading features from CSV: {args.data}")
        df_feats = load_features_from_csv(args.data, art_dir=args.models)
    elif args.eve:
        print(f"[INFO] Parsing Suricata EVE log: {args.eve}")
        df_feats = suricata_eve_to_features_df(args.eve, art_dir=args.models)
    else:  # args.zeek
        print(f"[INFO] Parsing Zeek conn.log: {args.zeek}")
        df_feats = zeek_conn_to_features_df(args.zeek, art_dir=args.models)

    if df_feats.empty:
        raise SystemExit("[ERROR] No flows found to classify.")

    # ---------------------------------------------------------------- predict
    if args.mode == "hier":
        print("[INFO] Running hierarchical predictions (normal / dos / other_attack)…")
        df_out = save_predictions_csv(
            df_feats, args.out, mode="hier", art_dir=args.models
        )
    else:
        print("[INFO] Running flat predictions (binary + tri-class)…")
        df_out = save_predictions_csv(
            df_feats, args.out, mode="flat", art_dir=args.models
        )

    print(f"[OK] Wrote predictions to: {args.out}")

    if "final_label" in df_out.columns:
        print("\n[SUMMARY] Final label distribution:")
        print(df_out["final_label"].value_counts())
    elif "bin_label" in df_out.columns:
        print("\n[SUMMARY] Binary label distribution (0=normal, 1=malicious):")
        print(df_out["bin_label"].value_counts())


if __name__ == "__main__":
    main()
