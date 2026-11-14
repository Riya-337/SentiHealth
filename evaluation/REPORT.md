# SentiHealth detection models: measured results

Generated 2026-11-14T18:10:04+00:00. **Data: synthetic** (`ml/simulate_events.py`), test period 2025-03-14 08:38:00+00:00 to 2025-03-16 23:58:00+00:00, 50,130 rows (Low 49,568 / Medium 209 / High 353). Attack family held out of training: `credential_stuffing`.

## Tier classification (test period)

| System | Accuracy | Macro P | Macro R | Macro F1 | High recall | High precision | ROC-AUC | ECE |
|---|---|---|---|---|---|---|---|---|
| XGBoost (calibrated) | 0.9993 | 0.968 | 0.980 | 0.974 | 0.997 | 0.981 | 0.992 | 0.001 |
| XGBoost + cost policy | 0.9992 | 0.957 | 0.988 | 0.972 | 0.997 | 0.981 | 0.992 | 0.001 |
| Random Forest (single, calibrated) + cost policy | 0.9992 | 0.958 | 0.987 | 0.972 | 1.000 | 0.981 | 0.994 | 0.001 |
| Rules only (deployed: failed logins) | 0.9921 | 0.976 | 0.559 | 0.651 | 0.164 | 0.935 | n/a | n/a |
| Expert rules only (thresholds) | 0.7869 | 0.543 | 0.829 | 0.556 | 0.997 | 0.616 | n/a | n/a |
| XGBoost + cost policy + rules (max tier) | 0.9991 | 0.952 | 0.981 | 0.967 | 0.997 | 0.970 | n/a | n/a |
| Legacy 5-model ensemble | 0.9989 | 0.964 | 0.952 | 0.958 | 0.994 | 0.983 | 1.000 | 0.015 |
| Legacy member: rf | 0.9986 | 0.971 | 0.921 | 0.944 | 0.989 | 0.983 | 0.996 | 0.014 |
| Legacy member: gb | 0.9991 | 0.984 | 0.947 | 0.964 | 0.994 | 0.986 | 0.988 | 0.020 |
| Legacy member: svm | 0.9979 | 0.906 | 0.966 | 0.934 | 0.994 | 0.867 | 0.999 | 0.019 |
| Legacy member: lr | 0.9979 | 0.926 | 0.912 | 0.918 | 0.992 | 0.931 | 0.998 | 0.014 |
| Legacy member: xgb | 0.9989 | 0.952 | 0.969 | 0.960 | 0.989 | 0.980 | 1.000 | 0.008 |

## Per-family detection (XGBoost + cost policy)

| Family | Rows | Correct tier | Row detection (>= Medium) | Campaign detection |
|---|---|---|---|---|
| brute_force | 58 | 1.000 | 1.000 | 1.000 (6 campaigns) |
| brute_force_slow (stealthy) | 117 | 1.000 | 1.000 | 1.000 (1 campaigns) |
| ddos_mild | 27 | 1.000 | 1.000 | 1.000 (1 campaigns) |
| ddos_severe | 196 | 1.000 | 1.000 | 1.000 (1 campaigns) |
| exfiltration | 67 | 0.985 | 0.985 | 1.000 (2 campaigns) |
| insider_offhours (stealthy) | 65 | 0.892 | 0.892 | 1.000 (3 campaigns) |
| normal | 49,553 | 0.999 | false alarms 0.0009 (High 0.0004) | |
| ransomware | 17 | 1.000 | 1.000 | 1.000 (1 campaigns) |
| recon | 30 | 0.933 | 0.067 | 0.500 (2 campaigns) |

## Isolation Forest (unsupervised, trained on normal rows only)

ROC-AUC attack vs normal: 1.000

| Threshold | False alarms (normal) | Recall (all attacks) | Recall on held-out family |
|---|---|---|---|
| fpr_1pct | 0.0252 | 1.000 | 1.000 |
| fpr_5pct | 0.1044 | 1.000 | 1.000 |
| fpr_10pct | 0.1616 | 1.000 | 1.000 |

Held-out family `credential_stuffing` (152 rows, never in training): XGBoost row detection 0.35526315789473684, campaign detection 1.0, Random Forest row detection 0.7894736842105263.

## Latency

XGBoost (calibrated): 0.005 ms/row in batch, 0.93 ms for a single row.
Legacy 5-model ensemble: 0.126 ms/row in batch (trained on 20,000 rows).

## Limits

- Every number above is on simulated data. Normal behaviour and attacks were written by the same author as the features, so real-world performance is unknown until the pipeline is run on real logs.
- No number in this file is adjusted, filtered or re-sampled to look better or worse; `ml/evaluate.py` writes what it measures.
