"""
train_model.py
--------------
Production-grade ML training pipeline for network intrusion detection.
Assignment 04 - Advanced Track (AI, Automation & Security Engineering)

Pipeline: load → validate → preprocess → train (RF, XGBoost, NN) → save artifacts
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
import yaml
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
from sklearn.base import clone
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectKBest, mutual_info_classif
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold, train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import LabelEncoder, MinMaxScaler, StandardScaler
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

RANDOM_STATE = 42
np.random.seed(RANDOM_STATE)

# Columns that should never be used as model features
EXCLUDE_COLS = {"label", "label_binary"}


def load_config(config_path: str = "config.yaml") -> dict:
    """Load YAML configuration file."""
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with open(path, "r") as f:
        return yaml.safe_load(f)


def compute_checksum(filepath: str) -> str:
    """Compute MD5 checksum for dataset versioning."""
    h = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_data(config: dict) -> pd.DataFrame:
    """
    Load dataset from CSV with basic validation.

    Raises:
        FileNotFoundError: if dataset path does not exist.
        ValueError: if schema or row count checks fail.
    """
    ds_cfg = config["dataset"]
    path = ds_cfg["path"]

    if not Path(path).exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    logger.info("Loading dataset from %s", path)
    df = pd.read_csv(path)
    checksum = compute_checksum(path)
    logger.info("Dataset checksum (MD5): %s", checksum)

    label_col = ds_cfg["label_column"]
    if label_col not in df.columns:
        raise ValueError(f"Label column '{label_col}' not found in dataset.")

    min_rows = ds_cfg.get("expected_min_rows", 1000)
    if len(df) < min_rows:
        raise ValueError(f"Dataset has {len(df)} rows; expected at least {min_rows}.")

    feature_cols = [c for c in df.columns if c not in EXCLUDE_COLS]
    min_feats = ds_cfg.get("expected_min_features", 10)
    if len(feature_cols) < min_feats:
        raise ValueError(
            f"Dataset has {len(feature_cols)} features; expected at least {min_feats}."
        )

    logger.info("Loaded %d rows, %d columns", len(df), len(df.columns))
    return df


def validate_data(df: pd.DataFrame, config: dict) -> dict:
    """
    Run data quality checks: nulls, duplicates, outliers, class distribution.

    Returns:
        Dictionary of quality report metrics.
    """
    report: dict = {
        "total_rows": len(df),
        "total_columns": len(df.columns),
        "null_counts": df.isnull().sum().to_dict(),
        "total_nulls": int(df.isnull().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
    }

    label_col = config["dataset"]["label_column"]
    report["class_distribution"] = df[label_col].value_counts().to_dict()

    numeric_cols = df.select_dtypes(include=[np.number]).columns
    outlier_counts = {}
    for col in numeric_cols:
        if col in EXCLUDE_COLS:
            continue
        q1, q3 = df[col].quantile(0.25), df[col].quantile(0.75)
        iqr = q3 - q1
        if iqr == 0:
            continue
        lower, upper = q1 - 3 * iqr, q3 + 3 * iqr
        outlier_counts[col] = int(((df[col] < lower) | (df[col] > upper)).sum())
    report["outlier_counts"] = outlier_counts

    logger.info("Validation — nulls: %d, duplicates: %d", report["total_nulls"], report["duplicate_rows"])
    logger.info("Class distribution: %s", report["class_distribution"])
    return report


def preprocess(
    df: pd.DataFrame,
    config: dict,
) -> Tuple[np.ndarray, np.ndarray, List[str], LabelEncoder, object, dict]:
    """
    Feature engineering: clean data, encode labels, scale features, SMOTE.

    Returns:
        X, y, feature_names, label_encoder, scaler, split_info
    """
    prep_cfg = config["preprocessing"]
    label_col = config["dataset"]["label_column"]
    split_cfg = config["splits"]

    df = df.copy()

    if prep_cfg.get("remove_duplicates", True):
        before = len(df)
        df = df.drop_duplicates()
        logger.info("Removed %d duplicate rows", before - len(df))

    feature_cols = [c for c in df.columns if c not in EXCLUDE_COLS]

    # Impute missing values
    strategy = prep_cfg.get("handle_missing", "median")
    for col in feature_cols:
        if df[col].isnull().any():
            fill_val = df[col].median() if strategy == "median" else df[col].mean()
            df[col] = df[col].fillna(fill_val)

    X_raw = df[feature_cols].values.astype(np.float64)
    y_raw = df[label_col].values

    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y_raw)

    # Train / val / test split (70/15/15)
    test_size = split_cfg["test_ratio"]
    val_size = split_cfg["val_ratio"] / (1 - test_size)

    X_temp, X_test, y_temp, y_test = train_test_split(
        X_raw, y,
        test_size=test_size,
        random_state=RANDOM_STATE,
        stratify=y if split_cfg.get("stratify", True) else None,
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp,
        test_size=val_size,
        random_state=RANDOM_STATE,
        stratify=y_temp if split_cfg.get("stratify", True) else None,
    )

    # Scaling
    scaler_name = prep_cfg.get("scaler", "StandardScaler")
    scaler = StandardScaler() if scaler_name == "StandardScaler" else MinMaxScaler()
    X_train = scaler.fit_transform(X_train)
    X_val = scaler.transform(X_val)
    X_test = scaler.transform(X_test)

    selected_features = feature_cols.copy()

    # Feature selection via mutual information
    fs_cfg = prep_cfg.get("feature_selection", {})
    if fs_cfg.get("enabled", False):
        top_k = min(fs_cfg.get("top_k", 35), X_train.shape[1])
        selector = SelectKBest(mutual_info_classif, k=top_k)
        X_train = selector.fit_transform(X_train, y_train)
        X_val = selector.transform(X_val)
        X_test = selector.transform(X_test)
        mask = selector.get_support()
        selected_features = [f for f, keep in zip(feature_cols, mask) if keep]
        logger.info("Selected top %d features via mutual information", top_k)

    # SMOTE on training set only (avoid data leakage)
    smote_cfg = prep_cfg.get("smote", {})
    if smote_cfg.get("enabled", False):
        k = min(smote_cfg.get("k_neighbors", 5), min(np.bincount(y_train)) - 1)
        if k >= 1:
            smote = SMOTE(random_state=RANDOM_STATE, k_neighbors=k)
            X_train, y_train = smote.fit_resample(X_train, y_train)
            logger.info("Applied SMOTE — training set now has %d samples", len(y_train))

    split_info = {
        "train_size": len(y_train),
        "val_size": len(y_val),
        "test_size": len(y_test),
        "X_val": X_val,
        "y_val": y_val,
        "X_test": X_test,
        "y_test": y_test,
    }

    return X_train, y_train, selected_features, label_encoder, scaler, split_info


def evaluate_cv(
    model,
    X: np.ndarray,
    y: np.ndarray,
    cv_folds: int = 5,
) -> dict:
    """Run stratified k-fold cross-validation and return mean metrics."""
    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=RANDOM_STATE)
    accs, f1s, precs, recs = [], [], [], []

    for train_idx, val_idx in cv.split(X, y):
        X_tr, X_va = X[train_idx], X[val_idx]
        y_tr, y_va = y[train_idx], y[val_idx]

        model_clone = _clone_model(model)
        model_clone.fit(X_tr, y_tr)
        preds = model_clone.predict(X_va)

        accs.append(accuracy_score(y_va, preds))
        f1s.append(f1_score(y_va, preds, average="weighted", zero_division=0))
        precs.append(precision_score(y_va, preds, average="weighted", zero_division=0))
        recs.append(recall_score(y_va, preds, average="weighted", zero_division=0))

    return {
        "cv_accuracy": float(np.mean(accs)),
        "cv_f1": float(np.mean(f1s)),
        "cv_precision": float(np.mean(precs)),
        "cv_recall": float(np.mean(recs)),
    }


def _clone_model(model):
    """Clone estimator for cross-validation folds."""
    return clone(model)


def train_models(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    config: dict,
) -> Tuple[dict, pd.DataFrame]:
    """
    Train Random Forest, XGBoost, and Neural Network with hyperparameter tuning.

    Returns:
        trained_models dict, training_log DataFrame
    """
    search_cfg = config["hyperparameter_search"]
    models_cfg = config["models"]
    results: dict = {}
    log_rows: List[dict] = []

    n_classes = len(np.unique(y_train))
    is_binary = n_classes == 2

    # --- Random Forest ---
    if models_cfg.get("random_forest", {}).get("enabled", True):
        logger.info("Training Random Forest...")
        rf_cfg = models_cfg["random_forest"]
        rf_base = RandomForestClassifier(
            random_state=RANDOM_STATE,
            class_weight="balanced",
            n_jobs=-1,
        )
        t0 = time.time()
        rf_search = RandomizedSearchCV(
            rf_base,
            param_distributions=rf_cfg["param_grid"],
            n_iter=search_cfg.get("n_iter", 8),
            cv=StratifiedKFold(n_splits=rf_cfg["cv_folds"], shuffle=True, random_state=RANDOM_STATE),
            scoring=search_cfg.get("scoring", "f1"),
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )
        rf_search.fit(X_train, y_train)
        rf_time = time.time() - t0
        rf_model = rf_search.best_estimator_
        rf_metrics = _eval_model(rf_model, X_val, y_val, is_binary)
        rf_cv = evaluate_cv(rf_base, X_train, y_train, rf_cfg["cv_folds"])
        results["random_forest"] = {
            "model": rf_model,
            "best_params": rf_search.best_params_,
            "metrics": rf_metrics,
            "cv_metrics": rf_cv,
            "training_time": rf_time,
        }
        log_rows.append(_log_row("Random Forest", rf_metrics, rf_cv, rf_time, rf_search.best_params_))
        logger.info("RF best F1: %.4f (%.1fs)", rf_metrics["f1"], rf_time)

    # --- XGBoost ---
    if models_cfg.get("xgboost", {}).get("enabled", True):
        logger.info("Training XGBoost...")
        xgb_cfg = models_cfg["xgboost"]
        scale_pos = (y_train == 0).sum() / max((y_train == 1).sum(), 1)
        xgb_base = XGBClassifier(
            random_state=RANDOM_STATE,
            eval_metric="logloss" if is_binary else "mlogloss",
            use_label_encoder=False,
            scale_pos_weight=scale_pos if is_binary else 1,
            n_jobs=-1,
        )
        t0 = time.time()
        xgb_search = RandomizedSearchCV(
            xgb_base,
            param_distributions=xgb_cfg["param_grid"],
            n_iter=search_cfg.get("n_iter", 8),
            cv=StratifiedKFold(n_splits=xgb_cfg["cv_folds"], shuffle=True, random_state=RANDOM_STATE),
            scoring=search_cfg.get("scoring", "f1"),
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )
        xgb_search.fit(X_train, y_train)
        xgb_time = time.time() - t0
        xgb_model = xgb_search.best_estimator_
        xgb_metrics = _eval_model(xgb_model, X_val, y_val, is_binary)
        xgb_cv = evaluate_cv(xgb_base, X_train, y_train, xgb_cfg["cv_folds"])
        results["xgboost"] = {
            "model": xgb_model,
            "best_params": xgb_search.best_params_,
            "metrics": xgb_metrics,
            "cv_metrics": xgb_cv,
            "training_time": xgb_time,
        }
        log_rows.append(_log_row("XGBoost", xgb_metrics, xgb_cv, xgb_time, xgb_search.best_params_))
        logger.info("XGBoost best F1: %.4f (%.1fs)", xgb_metrics["f1"], xgb_time)

    # --- Neural Network (sklearn MLPClassifier) ---
    if models_cfg.get("neural_network", {}).get("enabled", True):
        logger.info("Training Neural Network...")
        nn_cfg = models_cfg["neural_network"]
        nn_base = MLPClassifier(
            hidden_layer_sizes=(128, 64),
            activation="relu",
            max_iter=200,
            random_state=RANDOM_STATE,
            early_stopping=True,
            validation_fraction=0.1,
        )
        t0 = time.time()
        nn_search = RandomizedSearchCV(
            nn_base,
            param_distributions={
                "learning_rate_init": nn_cfg["param_grid"].get("learning_rate", [0.001]),
                "batch_size": nn_cfg["param_grid"].get("batch_size", [128]),
                "alpha": [1e-4, 1e-3],
            },
            n_iter=min(search_cfg.get("n_iter", 8), 6),
            cv=StratifiedKFold(n_splits=nn_cfg["cv_folds"], shuffle=True, random_state=RANDOM_STATE),
            scoring=search_cfg.get("scoring", "f1"),
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )
        nn_search.fit(X_train, y_train)
        nn_time = time.time() - t0
        nn_model = nn_search.best_estimator_
        nn_metrics = _eval_model(nn_model, X_val, y_val, is_binary)
        nn_cv = evaluate_cv(nn_base, X_train, y_train, nn_cfg["cv_folds"])
        results["neural_network"] = {
            "model": nn_model,
            "best_params": nn_search.best_params_,
            "metrics": nn_metrics,
            "cv_metrics": nn_cv,
            "training_time": nn_time,
            "loss_curve": getattr(nn_model, "loss_curve_", None),
        }
        log_rows.append(_log_row("Neural Network", nn_metrics, nn_cv, nn_time, nn_search.best_params_))
        logger.info("NN best F1: %.4f (%.1fs)", nn_metrics["f1"], nn_time)

    training_log = pd.DataFrame(log_rows)
    return results, training_log


def _eval_model(model, X_val, y_val, is_binary: bool) -> dict:
    """Compute validation metrics for a trained model."""
    preds = model.predict(X_val)
    metrics = {
        "accuracy": float(accuracy_score(y_val, preds)),
        "precision": float(precision_score(y_val, preds, average="weighted", zero_division=0)),
        "recall": float(recall_score(y_val, preds, average="weighted", zero_division=0)),
        "f1": float(f1_score(y_val, preds, average="weighted", zero_division=0)),
    }
    try:
        if is_binary and hasattr(model, "predict_proba"):
            proba = model.predict_proba(X_val)[:, 1]
            metrics["roc_auc"] = float(roc_auc_score(y_val, proba))
        elif hasattr(model, "predict_proba"):
            proba = model.predict_proba(X_val)
            metrics["roc_auc"] = float(roc_auc_score(y_val, proba, multi_class="ovr", average="weighted"))
        else:
            metrics["roc_auc"] = float("nan")
    except Exception:
        metrics["roc_auc"] = float("nan")
    return metrics


def _log_row(name, metrics, cv_metrics, train_time, best_params) -> dict:
    return {
        "model": name,
        "accuracy": metrics["accuracy"],
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1": metrics["f1"],
        "roc_auc": metrics.get("roc_auc"),
        "cv_accuracy": cv_metrics["cv_accuracy"],
        "cv_f1": cv_metrics["cv_f1"],
        "training_time_sec": round(train_time, 2),
        "best_params": json.dumps(best_params),
        "timestamp": datetime.utcnow().isoformat(),
    }


def save_artifacts(
    results: dict,
    training_log: pd.DataFrame,
    feature_names: List[str],
    label_encoder: LabelEncoder,
    scaler: object,
    config: dict,
    split_info: dict,
) -> str:
    """
    Persist best model, preprocessing pipeline, feature list, and training log.

    Returns:
        Path to artifacts directory.
    """
    out_cfg = config["output"]
    artifacts_dir = Path(out_cfg["artifacts_dir"])
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    version = out_cfg.get("model_version", "v1.0")
    best_name = max(results, key=lambda k: results[k]["metrics"]["f1"])
    best_result = results[best_name]

    model_filename = f"best_model_{version}.pkl"
    model_path = artifacts_dir / model_filename
    joblib.dump(best_result["model"], model_path)
    logger.info("Saved best model (%s) to %s", best_name, model_path)

    preprocessing = {
        "scaler": scaler,
        "label_encoder": label_encoder,
        "feature_names": feature_names,
        "best_model_name": best_name,
        "config": config,
    }
    prep_path = artifacts_dir / "preprocessing_pipeline.pkl"
    joblib.dump(preprocessing, prep_path)

    # Save all models for comparison in evaluation
    all_models_path = artifacts_dir / f"all_models_{version}.pkl"
    joblib.dump({k: v["model"] for k, v in results.items()}, all_models_path)

    feature_list_path = artifacts_dir / "feature_list.txt"
    with open(feature_list_path, "w") as f:
        f.write("\n".join(feature_names))

    log_path = artifacts_dir / out_cfg.get("log_file", "training_log.csv")
    training_log.to_csv(log_path, index=False)

    # Save test set for evaluation script
    test_data = {
        "X_test": split_info["X_test"],
        "y_test": split_info["y_test"],
    }
    joblib.dump(test_data, artifacts_dir / "test_data.pkl")

    metadata = {
        "model_version": version,
        "best_model": best_name,
        "best_metrics": best_result["metrics"],
        "feature_count": len(feature_names),
        "train_size": split_info["train_size"],
        "created_at": datetime.utcnow().isoformat(),
    }
    with open(artifacts_dir / "model_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    logger.info("All artifacts saved to %s", artifacts_dir)
    return str(artifacts_dir)


def main(config_path: str = "config.yaml") -> None:
    """Orchestrate the full training pipeline."""
    logger.info("=" * 60)
    logger.info("ML Threat Detection Training Pipeline")
    logger.info("=" * 60)

    try:
        config = load_config(config_path)
        df = load_data(config)
        validate_data(df, config)
        X_train, y_train, feature_names, label_encoder, scaler, split_info = preprocess(df, config)
        results, training_log = train_models(
            X_train, y_train,
            split_info["X_val"], split_info["y_val"],
            config,
        )
        artifacts_dir = save_artifacts(
            results, training_log, feature_names,
            label_encoder, scaler, config, split_info,
        )

        logger.info("Training complete. Artifacts: %s", artifacts_dir)
        print("\n" + "=" * 60)
        print("TRAINING SUMMARY")
        print("=" * 60)
        print(training_log[["model", "accuracy", "precision", "recall", "f1", "roc_auc", "training_time_sec"]].to_string(index=False))
        print("=" * 60)

    except Exception as exc:
        logger.error("Pipeline failed: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
