# Dashboard Walkthrough — `bonus/dashboard.py`

## Run it

```bash
cd Assignment_05/   # this project's root folder
pip install streamlit
streamlit run bonus/dashboard.py
```

Opens at `http://localhost:8501`.

## What it does

1. **Sidebar** — a threshold slider (-0.5 to 0.3) and a reminder of the six
   expected feature columns (with automatic UNSW-NB15/CICIDS2017 alias
   resolution, same as `anomaly_detector.py`).
2. **Upload a CSV** — try `sample_data/network_traffic_dataset.csv` or
   `sample_data/unsw_nb15_style_dataset.csv`.
3. If `outputs/isolation_forest_model.pkl` and `outputs/standard_scaler.pkl`
   already exist (from running `anomaly_detector.py --mode train`), the
   dashboard scores your upload with that trained pipeline. Otherwise it
   trains a fresh Isolation Forest on the uploaded file on the spot.
4. **Metrics row** — total rows, flagged anomalies (count + %), and the
   active threshold.
5. **Live precision/recall/F1** — appears automatically if the uploaded CSV
   has a `label` or `label_binary` column.
6. **Score distribution histogram** — anomaly scores with the current
   threshold marked.
7. **Normal vs. anomaly pie chart** and a **top-10 most anomalous rows**
   table.
8. **Full results table** (first 500 rows) plus a **CSV download button**
   with every row's anomaly score and flag.

## Verified behavior

This app was smoke-tested in this environment with
`streamlit run bonus/dashboard.py --server.headless true` — it starts
cleanly (HTTP 200, no server errors) and its core scoring path (feature
resolution → scaling → `decision_function` → thresholding) was verified
directly against `sample_data/network_traffic_dataset.csv` using the saved
model/scaler, correctly flagging 211 of 2,000 sampled rows at the default
threshold. A literal screenshot could not be captured because this is a
text/API-only execution environment without a browser to render Streamlit's
UI — running the command above will show the live interface.
