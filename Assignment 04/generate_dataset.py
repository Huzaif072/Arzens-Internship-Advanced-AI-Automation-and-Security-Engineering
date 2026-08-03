"""
generate_dataset.py
--------------------
Generates a synthetic network-flow dataset that mimics the structure and
statistical shape of CICIDS2017 (flow duration, packet/byte stats, flags,
protocol info), since the real dataset was not provided.

Classes (imbalanced, like real CICIDS2017):
    Benign, DoS, PortScan, BruteForce, WebAttack, Infiltration, Botnet

Output: network_traffic_dataset.csv  (50,000+ rows, 40+ numeric features)
"""

import numpy as np
import pandas as pd

RANDOM_SEED = 42
rng = np.random.default_rng(RANDOM_SEED)

N_TOTAL = 55000

# Realistic class imbalance (Benign dominates, like real network traffic)
CLASS_WEIGHTS = {
    "Benign": 0.78,
    "DoS": 0.09,
    "PortScan": 0.05,
    "BruteForce": 0.03,
    "WebAttack": 0.025,
    "Infiltration": 0.01,
    "Botnet": 0.015,
}

PROTOCOLS = [6, 17, 1]  # TCP, UDP, ICMP


def sample_counts():
    labels = list(CLASS_WEIGHTS.keys())
    probs = np.array(list(CLASS_WEIGHTS.values()))
    counts = (probs * N_TOTAL).round().astype(int)
    counts[0] += N_TOTAL - counts.sum()  # fix rounding drift onto Benign
    return dict(zip(labels, counts))


def gen_class_block(label, n, rng):
    """Generate feature rows for one class with its own statistical profile."""

    # Each class gets distinct central tendencies so a classifier can separate them
    profiles = {
        "Benign": dict(dur=(2e5, 3e5), fwd_pkts=(8, 6), bwd_pkts=(7, 5),
                       fwd_bytes=(600, 400), bwd_bytes=(500, 350), flag_rate=0.05),
        "DoS": dict(dur=(500, 400), fwd_pkts=(300, 150), bwd_pkts=(5, 4),
                    fwd_bytes=(15000, 6000), bwd_bytes=(200, 150), flag_rate=0.4),
        "PortScan": dict(dur=(50, 40), fwd_pkts=(2, 1), bwd_pkts=(1, 1),
                          fwd_bytes=(80, 40), bwd_bytes=(40, 20), flag_rate=0.6),
        "BruteForce": dict(dur=(3000, 2000), fwd_pkts=(20, 10), bwd_pkts=(18, 9),
                            fwd_bytes=(1200, 500), bwd_bytes=(900, 400), flag_rate=0.3),
        "WebAttack": dict(dur=(8000, 5000), fwd_pkts=(15, 8), bwd_pkts=(12, 6),
                           fwd_bytes=(3000, 1500), bwd_bytes=(2500, 1200), flag_rate=0.2),
        "Infiltration": dict(dur=(4e5, 2e5), fwd_pkts=(40, 20), bwd_pkts=(35, 18),
                              fwd_bytes=(20000, 9000), bwd_bytes=(18000, 8000), flag_rate=0.1),
        "Botnet": dict(dur=(1e5, 6e4), fwd_pkts=(25, 12), bwd_pkts=(20, 10),
                       fwd_bytes=(2500, 1000), bwd_bytes=(2000, 900), flag_rate=0.15),
    }
    p = profiles[label]

    def pos(mean, std, size):
        return np.clip(rng.normal(mean, std, size), 0, None)

    flow_duration = pos(*p["dur"], n)
    fwd_pkts = pos(*p["fwd_pkts"], n).round()
    bwd_pkts = pos(*p["bwd_pkts"], n).round()
    fwd_bytes = pos(*p["fwd_bytes"], n)
    bwd_bytes = pos(*p["bwd_bytes"], n)

    total_pkts = fwd_pkts + bwd_pkts
    total_bytes = fwd_bytes + bwd_bytes

    df = pd.DataFrame({
        "flow_duration": flow_duration,
        "total_fwd_packets": fwd_pkts,
        "total_bwd_packets": bwd_pkts,
        "total_fwd_bytes": fwd_bytes,
        "total_bwd_bytes": bwd_bytes,
        "total_packets": total_pkts,
        "total_bytes": total_bytes,
        "fwd_packet_len_max": fwd_bytes / np.maximum(fwd_pkts, 1) * rng.uniform(1.2, 2.0, n),
        "fwd_packet_len_min": fwd_bytes / np.maximum(fwd_pkts, 1) * rng.uniform(0.1, 0.5, n),
        "fwd_packet_len_mean": fwd_bytes / np.maximum(fwd_pkts, 1),
        "fwd_packet_len_std": pos(50, 30, n),
        "bwd_packet_len_max": bwd_bytes / np.maximum(bwd_pkts, 1) * rng.uniform(1.2, 2.0, n),
        "bwd_packet_len_min": bwd_bytes / np.maximum(bwd_pkts, 1) * rng.uniform(0.1, 0.5, n),
        "bwd_packet_len_mean": bwd_bytes / np.maximum(bwd_pkts, 1),
        "bwd_packet_len_std": pos(40, 25, n),
        "flow_bytes_per_sec": total_bytes / np.maximum(flow_duration, 1) * 1e6,
        "flow_packets_per_sec": total_pkts / np.maximum(flow_duration, 1) * 1e6,
        "flow_iat_mean": pos(1000, 800, n),
        "flow_iat_std": pos(500, 400, n),
        "flow_iat_max": pos(5000, 3000, n),
        "flow_iat_min": pos(10, 8, n),
        "fwd_iat_total": pos(2000, 1500, n),
        "fwd_iat_mean": pos(200, 150, n),
        "fwd_iat_std": pos(100, 80, n),
        "bwd_iat_total": pos(1800, 1400, n),
        "bwd_iat_mean": pos(180, 140, n),
        "bwd_iat_std": pos(90, 70, n),
        "fwd_psh_flags": rng.binomial(1, p["flag_rate"], n),
        "bwd_psh_flags": rng.binomial(1, p["flag_rate"] * 0.6, n),
        "fwd_urg_flags": rng.binomial(1, p["flag_rate"] * 0.2, n),
        "fin_flag_count": rng.binomial(1, p["flag_rate"] * 0.5, n),
        "syn_flag_count": rng.binomial(1, p["flag_rate"], n),
        "rst_flag_count": rng.binomial(1, p["flag_rate"] * 0.4, n),
        "psh_flag_count": rng.binomial(1, p["flag_rate"] * 0.7, n),
        "ack_flag_count": rng.binomial(1, min(p["flag_rate"] * 1.5, 1.0), n),
        "urg_flag_count": rng.binomial(1, p["flag_rate"] * 0.1, n),
        "cwe_flag_count": rng.binomial(1, p["flag_rate"] * 0.05, n),
        "ece_flag_count": rng.binomial(1, p["flag_rate"] * 0.05, n),
        "down_up_ratio": bwd_bytes / np.maximum(fwd_bytes, 1),
        "avg_packet_size": total_bytes / np.maximum(total_pkts, 1),
        "avg_fwd_segment_size": fwd_bytes / np.maximum(fwd_pkts, 1),
        "avg_bwd_segment_size": bwd_bytes / np.maximum(bwd_pkts, 1),
        "init_win_bytes_fwd": rng.integers(0, 65535, n),
        "init_win_bytes_bwd": rng.integers(0, 65535, n),
        "act_data_pkt_fwd": pos(5, 4, n).round(),
        "min_seg_size_fwd": rng.integers(20, 60, n),
        "active_mean": pos(300, 200, n),
        "idle_mean": pos(1e5, 5e4, n),
        "subflow_fwd_bytes": fwd_bytes * rng.uniform(0.8, 1.0, n),
        "subflow_bwd_bytes": bwd_bytes * rng.uniform(0.8, 1.0, n),
        "protocol": rng.choice(PROTOCOLS, n, p=[0.75, 0.20, 0.05]),
        "destination_port": rng.integers(1, 65535, n),
    })

    df["label"] = label
    return df


def main():
    counts = sample_counts()
    blocks = [gen_class_block(label, n, rng) for label, n in counts.items()]
    df = pd.concat(blocks, ignore_index=True)

    # Shuffle rows so classes aren't grouped together
    df = df.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)

    # Inject realistic data-quality issues (as real captures have): missing
    # values, a few duplicate rows, and a handful of outliers.
    n_missing = int(0.01 * len(df))
    missing_cols = ["flow_iat_std", "bwd_packet_len_std", "active_mean"]
    for col in missing_cols:
        idx = rng.choice(df.index, size=n_missing // len(missing_cols), replace=False)
        df.loc[idx, col] = np.nan

    dup_idx = rng.choice(df.index, size=int(0.002 * len(df)), replace=False)
    df = pd.concat([df, df.loc[dup_idx]], ignore_index=True)

    outlier_idx = rng.choice(df.index, size=50, replace=False)
    df.loc[outlier_idx, "flow_duration"] *= 50

    # Binary label column alongside the multi-class one
    df["label_binary"] = np.where(df["label"] == "Benign", "Benign", "Attack")

    df.to_csv("network_traffic_dataset.csv", index=False)

    print(f"Generated {len(df):,} rows, {df.shape[1]} columns")
    print("\nClass distribution (multi-class):")
    print(df["label"].value_counts())
    print("\nClass distribution (binary):")
    print(df["label_binary"].value_counts())
    print(f"\nMissing values total: {df.isna().sum().sum()}")


if __name__ == "__main__":
    main()
