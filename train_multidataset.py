"""
Step 1 + 2: Multi-dataset training and evaluation (CICIDS2017 + CSE-CIC-IDS2018).

Run from E:\\cyber :   python train_multidataset.py

What it does
  1. Loads both datasets, normalises column names and labels to one schema.
  2. Aligns to the SAME feature list your current CICIDS2017 models use.
  3. Prints a distribution diagnostic (explains the ~51% cross-dataset result).
  4. Trains RF + XGBoost (binary and family) on three setups and reports:
        A. train 2017          -> test 2017 (held out) and 2018   (baseline)
        B. train 2018          -> test 2018 (held out) and 2017
        C. train 2017 + 2018   -> test 2017 (held out) and 2018 (held out)
  5. Saves new models to models/multidataset/ (does NOT touch existing models).

Splits are temporal blocks within each file (not random rows) to avoid
near-duplicate flow leakage.
"""
import glob, json, os, re, sys, time
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

# ----------------------------------------------------------------- CONFIG
ROOT = os.path.dirname(os.path.abspath(__file__))
RAW_2017 = os.path.join(ROOT, "data", "raw", "CICIDS2017")
RAW_2018 = os.path.join(ROOT, "data", "raw", "CSE_CIC_IDS2018")
EXISTING_MODEL = os.path.join(ROOT, "models", "random_forest_binary_cicids2017.pkl")
OUT_DIR = os.path.join(ROOT, "models", "multidataset")
REPORT_DIR = os.path.join(ROOT, "reports")
MAX_ROWS_PER_DATASET = 1_500_000   # cap for RAM; raise if you have memory
RANDOM_STATE = 42
os.makedirs(OUT_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

# ------------------------------------------------- column / label mapping
def norm_col(c: str) -> str:
    return re.sub(r"\s+", " ", str(c)).strip()

# CSE-CIC-IDS2018 short names -> CICIDS2017 names (CICFlowMeter versions differ)
ALIASES_2018 = {
    "Dst Port": "Destination Port", "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets",
    "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    "Fwd Pkt Len Max": "Fwd Packet Length Max", "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean", "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max", "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean", "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s", "Flow Pkts/s": "Flow Packets/s",
    "Fwd IAT Tot": "Fwd IAT Total", "Bwd IAT Tot": "Bwd IAT Total",
    "Fwd Header Len": "Fwd Header Length", "Bwd Header Len": "Bwd Header Length",
    "Fwd Pkts/s": "Fwd Packets/s", "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Min": "Min Packet Length", "Pkt Len Max": "Max Packet Length",
    "Pkt Len Mean": "Packet Length Mean", "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance",
    "FIN Flag Cnt": "FIN Flag Count", "SYN Flag Cnt": "SYN Flag Count",
    "RST Flag Cnt": "RST Flag Count", "PSH Flag Cnt": "PSH Flag Count",
    "ACK Flag Cnt": "ACK Flag Count", "URG Flag Cnt": "URG Flag Count",
    "CWE Flag Count": "CWE Flag Count", "ECE Flag Cnt": "ECE Flag Count",
    "Pkt Size Avg": "Average Packet Size", "Fwd Seg Size Avg": "Avg Fwd Segment Size",
    "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk", "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate", "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk", "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
    "Subflow Fwd Pkts": "Subflow Fwd Packets", "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets", "Subflow Bwd Byts": "Subflow Bwd Bytes",
    "Init Fwd Win Byts": "Init_Win_bytes_forward", "Init Bwd Win Byts": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd", "Fwd Seg Size Min": "min_seg_size_forward",
}

# Normalised label -> family used by your multiclass models. ADJUST to match
# multiclass_label_encoder.pkl classes if they differ.
def label_family(raw: str) -> str:
    s = re.sub(r"[^a-z0-9 ]", " ", str(raw).lower())
    s = re.sub(r"\s+", " ", s).strip()
    if s in ("benign", "normal"): return "Benign"
    if "heartbleed" in s: return "Heartbleed"
    if "infil" in s: return "Infiltration"
    if "ddos" in s or "loic" in s or "hoic" in s: return "DDoS"
    if "dos" in s: return "DoS"
    if "portscan" in s or "port scan" in s: return "PortScan"
    if "bot" in s: return "Botnet"
    if "ftp" in s or "ssh" in s or "brute" in s: return "BruteForce"
    if "web" in s or "sql" in s or "xss" in s: return "WebAttack"
    return "Other:" + s

# --------------------------------------------------------------- loading
def find_label_col(df):
    for c in df.columns:
        if c.lower() == "label":
            return c
    return None

def safe_aliases(cols, feature_cols, aliases):
    """Only rename a column if it is NOT already a wanted feature and the target is
    a wanted feature that is not already present. Prevents wrong renames when a
    dataset already uses the model's naming."""
    cols = set(cols)
    return {k: v for k, v in aliases.items()
            if k in cols and k not in feature_cols and v in feature_cols and v not in cols}

def file_columns(path):
    if path.lower().endswith(".parquet"):
        import pyarrow.parquet as pq
        return [norm_col(c) for c in pq.read_schema(path).names]
    return [norm_col(c) for c in pd.read_csv(path, nrows=0).columns]

def check_schema(feats, folder, name, aliases=None):
    """Cheap pre-flight: which model features are absent from every/any file?"""
    import difflib
    files = sorted(glob.glob(os.path.join(folder, "**", "*.parquet"), recursive=True) +
                   glob.glob(os.path.join(folder, "**", "*.csv"), recursive=True))
    missing_any = set()
    for f in files:
        cols = file_columns(f)
        if aliases:
            cols = [safe_aliases(cols, feats, aliases).get(c, c) for c in cols]
        missing_any |= set(feats) - set(cols)
        extras = [c for c in cols if c not in feats and c.lower() != "label"]
    if missing_any:
        print(f"   [!] {name}: features missing in at least one file: {sorted(missing_any)}")
        for m in sorted(missing_any):
            print(f"       closest columns to '{m}': {difflib.get_close_matches(m, extras, n=3, cutoff=0.4)}")
    else:
        print(f"   {name}: all {len(feats)} features present in every file")
    return missing_any

def read_any(path):
    if path.lower().endswith(".parquet"):
        return pd.read_parquet(path)
    return pd.read_csv(path, low_memory=False)

def load_dataset(folder, name, feature_cols, aliases=None):
    files = sorted(glob.glob(os.path.join(folder, "**", "*.parquet"), recursive=True) +
                   glob.glob(os.path.join(folder, "**", "*.csv"), recursive=True))
    if not files:
        sys.exit(f"[!] No .parquet/.csv files under {folder}")
    frames, per_file_cap = [], MAX_ROWS_PER_DATASET // len(files)
    for f in files:
        df = read_any(f)
        df.columns = [norm_col(c) for c in df.columns]
        if aliases:
            df = df.rename(columns=safe_aliases(df.columns, feature_cols, aliases))
        df = df.loc[:, ~df.columns.duplicated()].reset_index(drop=True)
        lab = find_label_col(df)
        if lab is None:
            print(f"   skip {os.path.basename(f)} (no Label column). Columns: {list(df.columns)[:8]}"); continue
        df = df[df[lab].astype(str).str.lower() != "label"].reset_index(drop=True)
        missing = [c for c in feature_cols if c not in df.columns]
        if missing:
            print(f"   [!] {os.path.basename(f)} missing {len(missing)} features, e.g. {missing[:5]} -> skipped")
            print(f"       file columns sample: {list(df.columns)[:10]}")
            continue
        X = df[feature_cols].apply(pd.to_numeric, errors="coerce")
        X["label_raw"] = df[lab].astype(str).str.strip()
        X["source_file"] = os.path.basename(f)
        X["pos"] = np.arange(len(X)) / max(len(X) - 1, 1)   # position in capture order
        if len(X) > per_file_cap:
            X = X.sample(per_file_cap, random_state=RANDOM_STATE).sort_values("pos")
        frames.append(X)
        print(f"   {name}: {os.path.basename(f)} -> {len(X):,} rows")
    if not frames:
        sys.exit(f"[!] {name}: no usable files. Fix ALIASES/feature list first.")
    d = pd.concat(frames, ignore_index=True)
    d[feature_cols] = d[feature_cols].replace([np.inf, -np.inf], np.nan)
    before = len(d)
    d = d.dropna(subset=feature_cols).drop_duplicates(subset=feature_cols + ["label_raw"])
    print(f"   {name}: cleaned {before:,} -> {len(d):,} rows")
    d["family"] = d["label_raw"].map(label_family)
    d["binary"] = (d["family"] != "Benign").astype(int)
    d["dataset"] = name
    return d

# -------------------------------------------------------------- splitting
def group_split(d, test_size=0.3, gap=0.02):
    """Files here are organised per attack type, so splitting by file would drop whole
    families from training. Instead split each file by capture order: first 70% train,
    last 30% test, with a small gap. Adjacent (near-duplicate) flows never straddle the
    boundary and every family appears in both sides."""
    cut = 1 - test_size
    tr = d[d["pos"] < cut - gap]
    te = d[d["pos"] >= cut]
    return tr, te, "temporal block split per file (70/30, 2% gap)"

# ---------------------------------------------------------------- models
def make_models(kind, n_classes=2):
    rf = RandomForestClassifier(n_estimators=200, n_jobs=-1, class_weight="balanced_subsample",
                                random_state=RANDOM_STATE)
    if kind == "binary":
        xgb = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1, subsample=0.8,
                            colsample_bytree=0.8, tree_method="hist", n_jobs=-1,
                            eval_metric="logloss", random_state=RANDOM_STATE)
    else:
        xgb = XGBClassifier(n_estimators=300, max_depth=8, learning_rate=0.1, subsample=0.8,
                            colsample_bytree=0.8, tree_method="hist", n_jobs=-1,
                            objective="multi:softprob", num_class=n_classes,
                            eval_metric="mlogloss", random_state=RANDOM_STATE)
    return {"RandomForest": rf, "XGBoost": xgb}

def balanced_sample_weight(y):
    classes, counts = np.unique(y, return_counts=True)
    w = {c: len(y) / (len(classes) * n) for c, n in zip(classes, counts)}
    return np.array([w[v] for v in y])

def score(y_true, y_pred, binary):
    avg = "binary" if binary else "macro"
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, average=avg, zero_division=0),
        "recall": recall_score(y_true, y_pred, average=avg, zero_division=0),
        "f1": f1_score(y_true, y_pred, average=avg, zero_division=0),
    }

def run_setup(tag, train_df, tests, feats, results, save=False, le=None):
    """tests: dict name -> DataFrame"""
    # binary
    for mname, model in make_models("binary").items():
        t0 = time.time()
        sw = balanced_sample_weight(train_df["binary"].values) if mname == "XGBoost" else None
        model.fit(train_df[feats].values, train_df["binary"].values, **({"sample_weight": sw} if sw is not None else {}))
        for tname, tdf in tests.items():
            m = score(tdf["binary"].values, model.predict(tdf[feats].values), True)
            results.append({"setup": tag, "task": "binary", "model": mname, "test_on": tname, "n_test": len(tdf), **m})
            print(f"   [{tag}] binary {mname:12s} on {tname:10s} acc={m['accuracy']:.4f} rec={m['recall']:.4f} f1={m['f1']:.4f}")
        if save:
            joblib.dump(model, os.path.join(OUT_DIR, f"{mname.lower()}_binary_multidataset.pkl"))
        print(f"      ({time.time()-t0:.0f}s)")
    # family: only classes with >=2 train samples
    vc = train_df["family"].value_counts()
    keep = vc[vc >= 2].index
    tr = train_df[train_df["family"].isin(keep)]
    enc = LabelEncoder().fit(tr["family"])
    for mname, model in make_models("multi", len(enc.classes_)).items():
        sw = balanced_sample_weight(enc.transform(tr["family"])) if mname == "XGBoost" else None
        model.fit(tr[feats].values, enc.transform(tr["family"]), **({"sample_weight": sw} if sw is not None else {}))
        for tname, tdf in tests.items():
            t = tdf[tdf["family"].isin(enc.classes_)]  # unseen families reported separately
            pred = enc.inverse_transform(model.predict(t[feats].values).astype(int))
            m = score(t["family"].values, pred, False)
            results.append({"setup": tag, "task": "family", "model": mname, "test_on": tname,
                            "n_test": len(t), "dropped_unseen_family_rows": len(tdf) - len(t), **m})
            print(f"   [{tag}] family {mname:12s} on {tname:10s} acc={m['accuracy']:.4f} macroF1={m['f1']:.4f}")
        if save:
            joblib.dump(model, os.path.join(OUT_DIR, f"{mname.lower()}_multiclass_multidataset.pkl"))
    if save:
        joblib.dump(enc, os.path.join(OUT_DIR, "multiclass_label_encoder_multidataset.pkl"))

# ------------------------------------------------------------------ main
def main():
    # Feature list: take it from the existing model so order matches the agents
    if os.path.exists(EXISTING_MODEL):
        m = joblib.load(EXISTING_MODEL)
        feats = [norm_col(c) for c in getattr(m, "feature_names_in_", [])]
        if not feats:
            sys.exit("[!] Existing model has no feature_names_in_. Provide the feature list manually.")
        print(f"Using {len(feats)} features from existing model.")
    else:
        sys.exit(f"[!] {EXISTING_MODEL} not found; run from the project root.")

    print("\nSchema pre-flight:")
    miss = check_schema(feats, RAW_2017, "CICIDS2017") | check_schema(feats, RAW_2018, "CSE2018", ALIASES_2018)
    if miss:
        print(f"   Dropping {len(miss)} feature(s) not common to both datasets. New models will use "
              f"{len(feats) - len(miss)} features (list saved in meta.json). Agents must select these columns.")
        feats = [f for f in feats if f not in miss]

    print("\nLoading CICIDS2017 ...")
    d17 = load_dataset(RAW_2017, "CICIDS2017", feats)
    print("\nLoading CSE-CIC-IDS2018 ...")
    d18 = load_dataset(RAW_2018, "CSE2018", feats, aliases=ALIASES_2018)

    # ---- diagnostics
    print("\n== Family distribution ==")
    print(pd.concat([d17["family"].value_counts().rename("2017"),
                     d18["family"].value_counts().rename("2018")], axis=1).fillna(0).astype(int))
    other = [f for f in pd.concat([d17, d18])["family"].unique() if f.startswith("Other:")]
    if other:
        print("\n[!] Unmapped labels (edit label_family):", other)

    med = pd.DataFrame({"median_2017": d17[feats].median(), "median_2018": d18[feats].median()})
    med["log10_ratio"] = np.log10((med.median_2018.abs() + 1) / (med.median_2017.abs() + 1))
    shifted = med.reindex(med.log10_ratio.abs().sort_values(ascending=False).index).head(15)
    print("\n== 15 most distribution-shifted features (median, 2018 vs 2017) ==")
    print(shifted.to_string())
    print("Large ratios (esp. time/IAT/duration) suggest a unit or definition mismatch, not just 'hard generalisation'.")
    shifted.to_csv(os.path.join(REPORT_DIR, "feature_shift_2017_vs_2018.csv"))

    # ---- splits
    tr17, te17, how17 = group_split(d17)
    tr18, te18, how18 = group_split(d18)
    print(f"\nSplit 2017: {how17} | Split 2018: {how18}")
    tests = {"CICIDS2017": te17, "CSE2018": te18}
    results = []

    print("\n== A. Train 2017 only ==");  run_setup("A_train2017", tr17, tests, feats, results)
    print("\n== B. Train 2018 only ==");  run_setup("B_train2018", tr18, tests, feats, results)
    print("\n== C. Train 2017 + 2018 =="); 
    combo = pd.concat([tr17, tr18], ignore_index=True)
    run_setup("C_combined", combo, tests, feats, results, save=True)

    out = pd.DataFrame(results)
    out.to_csv(os.path.join(REPORT_DIR, "multidataset_results.csv"), index=False)
    json.dump({"features": feats, "split_2017": how17, "split_2018": how18},
              open(os.path.join(OUT_DIR, "meta.json"), "w"), indent=2)
    print("\n== Summary ==")
    print(out[out.task == "binary"][["setup", "model", "test_on", "accuracy", "recall", "f1"]].round(4).to_string(index=False))
    print(f"\nSaved: {OUT_DIR}  and  {REPORT_DIR}\\multidataset_results.csv")

if __name__ == "__main__":
    main()