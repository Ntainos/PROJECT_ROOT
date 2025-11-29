# ml_rest_server.py
"""
Minimal ML REST API for NSA project.

- Loads two joblib models from ./models:
    rf_bin.joblib          -> normal vs attack
    rf_dos_vs_other.joblib -> dos vs other_attack (only if attack)

- Exposes one endpoint:
    POST /predict_one

  Request JSON:
    {
      "proto":   "tcp",
      "service": "http",
      "spkts":   10,
      "dpkts":   8,
      "sbytes":  1500,
      "dbytes":  2000,
      "dur":     0.45
    }

  Response JSON:
    {
      "bin_label":          "normal" | "attack",
      "dos_vs_other_label": "dos" | "other_attack" | null,
      "final_label":        "normal" | "dos" | "other_attack"
    }
"""

from pathlib import Path
from typing import Literal, Optional

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI
from pydantic import BaseModel


# ---------- Config & model loading -------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent
MODELS_DIR = PROJECT_ROOT / "models"


def load_model(filename: str):
    path = MODELS_DIR / filename
    if not path.exists():
        raise RuntimeError(f"Model file not found: {path}")
    return joblib.load(path)


print("[ML-API] Loading models from", MODELS_DIR)
model_bin = load_model("rf_bin.joblib")
model_dos = load_model("rf_dos_vs_other.joblib")
print("[ML-API] Models loaded.")


# ---------- Pydantic schemas -------------------------------------------------

class FlowInput(BaseModel):
    proto: str
    service: str
    spkts: int
    dpkts: int
    sbytes: int
    dbytes: int
    dur: float


class FlowOutput(BaseModel):
    bin_label: Literal["normal", "attack"]
    dos_vs_other_label: Optional[Literal["dos", "other_attack"]] = None
    final_label: Literal["normal", "dos", "other_attack"]


# ---------- Internal helper --------------------------------------------------

def _is_attack_label(raw) -> bool:
    """
    Try to interpret the output of the binary model.
    - If it's int-like: 1 = attack, 0 = normal
    - If it's string-like: "normal" -> normal, anything else -> attack
    """
    if isinstance(raw, (int, np.integer)):
        return int(raw) == 1
    s = str(raw).lower()
    return s != "normal"


def _is_dos_label(raw) -> bool:
    """
    Interpret the output of the dos-vs-other model.
    - If it's int-like: 1 = dos, 0 = other_attack
    - If it's string-like: "dos" -> dos, otherwise -> other_attack
    """
    if isinstance(raw, (int, np.integer)):
        return int(raw) == 1
    s = str(raw).lower()
    return s == "dos"


def classify_flow(row: dict) -> dict:
    """
    Given a dict with the 7 features, run both models and return labels.
    """
    df = pd.DataFrame([row])

    # 1) binary model: normal vs attack
    bin_raw = model_bin.predict(df)[0]
    is_attack = _is_attack_label(bin_raw)
    bin_label = "attack" if is_attack else "normal"

    dos_vs_other_label: Optional[str] = None
    final_label: str

    if not is_attack:
        final_label = "normal"
    else:
        # 2) second model: dos vs other_attack
        dos_raw = model_dos.predict(df)[0]
        is_dos = _is_dos_label(dos_raw)
        dos_vs_other_label = "dos" if is_dos else "other_attack"
        final_label = dos_vs_other_label

    return {
        "bin_label": bin_label,
        "dos_vs_other_label": dos_vs_other_label,
        "final_label": final_label,
    }


# ---------- FastAPI app ------------------------------------------------------

app = FastAPI(
    title="NSA ML Inference API",
    description="Simple REST API for normal / dos / other_attack classification.",
    version="1.0.0",
)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/predict_one", response_model=FlowOutput)
def predict_one(flow: FlowInput):
    """
    Classify a single flow into: normal / dos / other_attack.
    """
    result = classify_flow(flow.dict())
    return result
