"""
generate_unsw_style_dataset.py
--------------------------------
Practical Task 1 support script.

Kaggle (kaggle.com) is not reachable from this environment's network
allowlist, so the real UNSW-NB15 CSV could not be downloaded. This script
generates a second synthetic dataset that mirrors UNSW-NB15's *native*
column names (dur, spkts, dpkts, sbytes, dbytes, rate, proto, state) and,
deliberately, a harder separation problem than the Assignment 04
CICIDS2017-style generator: attack classes here have heavier distribution
overlap with normal traffic, mimicking a well-known property of UNSW-NB15
(it is generally considered a harder benchmark than CICIDS2017 because
several of its attack categories - Fuzzers, Analysis, Backdoor, Worms in
particular - produce flow statistics that resemble benign traffic much
more closely than DoS/PortScan-style attacks do).

Output: unsw_nb15_style_dataset.csv (~55,000 rows)
"""

import numpy as np
import pandas as pd

RANDOM_SEED = 42
rng = np.random.default_rng(RANDOM_SEED)

N_TOTAL = 55000

# UNSW-NB15's real attack_cat categories (proportions loosely mirror the
# well-known class imbalance of the real dataset, where Normal traffic and
# Generic dominate and rarer categories like Worms are a tiny fraction).
CLASS_WEIGHTS = {
    "Normal": 0.68,
    "Generic": 0.11,
    "Exploits": 0.06,
    "Fuzzers": 0.05,
    "DoS": 0.04,
    "Reconnaissance": 0.03,
    "Analysis": 0.015,
    "Backdoor": 0.01,
    "Shellcode": 0.004,
    "Worms": 0.001,
}

PROTOCOLS = [6, 17, 1]  # tcp, udp, icmp


def sample_counts():
    labels = list(CLASS_WEIGHTS.keys())
    probs = np.array(list(CLASS_WEIGHTS.values()))
    counts = (probs * N_TOTAL).round().astype(int)
    counts[0] += N_TOTAL - counts.sum()
    return dict(zip(labels, counts))


def gen_class_block(label, n, rng):
    """Generate dur/spkts/dpkts/sbytes/dbytes for one UNSW-NB15 class.

    Deliberately overlapping profiles for the "quiet" attack categories
    (Fuzzers, Analysis, Backdoor, Shellcode, Worms) so they sit close to
    Normal traffic in feature space - this is what makes UNSW-NB15 a
    harder benchmark than a CICIDS2017-style dataset dominated by loud
    DoS/PortScan traffic.
    """
    profiles = {
        # (dur mean,std), (spkts mean,std), (dpkts mean,std), (sbytes mean,std), (dbytes mean,std)
        "Normal":         dict(dur=(1.5, 2.0), spkts=(10, 8), dpkts=(9, 7), sbytes=(700, 500), dbytes=(650, 450)),
        "Generic":        dict(dur=(0.05, 0.05), spkts=(2, 1), dpkts=(1, 1), sbytes=(120, 60), dbytes=(60, 40)),
        "Exploits":       dict(dur=(0.8, 1.0), spkts=(18, 10), dpkts=(15, 9), sbytes=(2200, 1200), dbytes=(1800, 1000)),
        "Fuzzers":        dict(dur=(1.2, 1.8), spkts=(9, 7), dpkts=(8, 6), sbytes=(750, 550), dbytes=(680, 480)),  # overlaps Normal
        "DoS":            dict(dur=(0.02, 0.02), spkts=(400, 150), dpkts=(3, 2), sbytes=(18000, 7000), dbytes=(150, 100)),
        "Reconnaissance": dict(dur=(0.15, 0.2), spkts=(3, 2), dpkts=(2, 1), sbytes=(150, 70), dbytes=(80, 50)),
        "Analysis":       dict(dur=(1.4, 1.9), spkts=(11, 8), dpkts=(10, 7), sbytes=(720, 520), dbytes=(660, 460)),  # overlaps Normal
        "Backdoor":       dict(dur=(1.6, 2.1), spkts=(12, 9), dpkts=(10, 7), sbytes=(800, 550), dbytes=(700, 480)),  # overlaps Normal
        "Shellcode":      dict(dur=(0.3, 0.4), spkts=(6, 4), dpkts=(4, 3), sbytes=(900, 400), dbytes=(300, 200)),
        "Worms":          dict(dur=(1.3, 1.7), spkts=(10, 7), dpkts=(9, 6), sbytes=(710, 500), dbytes=(640, 440)),  # overlaps Normal
    }
    p = profiles[label]

    def pos(mean, std, size):
        return np.clip(rng.normal(mean, std, size), 1e-4, None)

    dur = pos(*p["dur"], n)
    spkts = pos(*p["spkts"], n).round()
    dpkts = pos(*p["dpkts"], n).round()
    sbytes = pos(*p["sbytes"], n)
    dbytes = pos(*p["dbytes"], n)
    rate = (spkts + dpkts) / dur

    proto = rng.choice(PROTOCOLS, size=n, p=[0.75, 0.20, 0.05])
    state = rng.choice(["FIN", "CON", "INT", "REQ"], size=n, p=[0.4, 0.35, 0.15, 0.10])

    return pd.DataFrame({
        "dur": dur, "spkts": spkts, "dpkts": dpkts,
        "sbytes": sbytes, "dbytes": dbytes, "rate": rate,
        "proto": proto, "state": state,
        "attack_cat": label,
        "label": "Normal" if label == "Normal" else "Attack",
        "label_binary": "Benign" if label == "Normal" else "Attack",
    })


def main():
    counts = sample_counts()
    blocks = [gen_class_block(label, n, rng) for label, n in counts.items() if n > 0]
    df = pd.concat(blocks, ignore_index=True)
    df = df.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)  # shuffle

    out_path = "sample_data/unsw_nb15_style_dataset.csv"
    df.to_csv(out_path, index=False)
    print(f"Wrote {out_path}: {df.shape[0]:,} rows x {df.shape[1]} columns")
    print(df["attack_cat"].value_counts())
    print(df["label"].value_counts())


if __name__ == "__main__":
    main()
