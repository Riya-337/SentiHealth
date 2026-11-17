# Deception with a safety guarantee: measured results

Generated 2026-11-17T09:22:27+00:00. **Synthetic data** (ml/simulate_events.py), 5 seeds, 28 days, 300 users per seed. Calibration on the validation period's legitimate sessions, evaluation on the test period. 'Legit rate' = share of legitimate sessions that were EVER served noise or decoys.

## Detector: xgb

| alpha | legit rate pooled (mean / max over seeds) | worst role, pooled | legit rate per-role gate (mean / max) | worst role, per-role gate | attack sessions deceived | attacker reads on decoys | attacker export on decoys |
|---|---|---|---|---|---|---|---|
| 0.1 | 0.0970 / 0.1105 | 0.1260 | 0.0987 / 0.1072 | 0.1013 | 0.9757 | 0.9862 | 0.9959 |
| 0.05 | 0.0497 / 0.0594 | 0.0754 | 0.0480 / 0.0549 | 0.0499 | 0.9687 | 0.9672 | 0.9831 |
| 0.02 | 0.0204 / 0.0265 | 0.0402 | 0.0177 / 0.0236 | 0.0225 | 0.9586 | 0.6491 | 0.7104 |
| 0.01 | 0.0076 / 0.0152 | 0.0174 | 0.0067 / 0.0115 | 0.0149 | 0.9268 | 0.3958 | 0.4323 |
| 0.005 | 0.0037 / 0.0060 | 0.0093 | 0.0019 / 0.0061 | 0.0053 | 0.7597 | 0.0000 | 0.0000 |

## Detector: iforest

| alpha | legit rate pooled (mean / max over seeds) | worst role, pooled | legit rate per-role gate (mean / max) | worst role, per-role gate | attack sessions deceived | attacker reads on decoys | attacker export on decoys |
|---|---|---|---|---|---|---|---|
| 0.1 | 0.0993 / 0.1105 | 0.1624 | 0.1011 / 0.1132 | 0.1115 | 0.8379 | 0.8214 | 0.9089 |
| 0.05 | 0.0500 / 0.0668 | 0.0813 | 0.0475 / 0.0543 | 0.0522 | 0.8072 | 0.7306 | 0.8171 |
| 0.02 | 0.0197 / 0.0228 | 0.0272 | 0.0168 / 0.0199 | 0.0204 | 0.5137 | 0.4798 | 0.5487 |
| 0.01 | 0.0089 / 0.0124 | 0.0114 | 0.0089 / 0.0124 | 0.0103 | 0.4462 | 0.2944 | 0.3353 |
| 0.005 | 0.0039 / 0.0054 | 0.0057 | 0.0021 / 0.0033 | 0.0030 | 0.2843 | 0.0000 | 0.0000 |

## Baseline: fixed threshold on the detector's probability (no guarantee)

| threshold | legit rate (mean over seeds) | worst role (mean) | attack sessions deceived |
|---|---|---|---|
| 0.5 | 0.0040 | 0.0127 | 0.9377 |
| 0.75 | 0.0028 | 0.0103 | 0.9265 |
| 0.9 | 0.0017 | 0.0062 | 0.9144 |

## Time-ordered calibration (alpha = 0.01, per-role gate)

Earlier half of the post-training sessions calibrates, later half is evaluated (not exchangeable if the halves differ).

| detector | legit rate (mean / max over seeds) | attack sessions deceived (mean) |
|---|---|---|
| xgb | 0.0119 / 0.0159 | 0.9434 |
| iforest | 0.0103 / 0.0142 | 0.4481 |

## Contaminated calibration (alpha = 0.01, xgb)

| attack sessions added (as share of legit) | legit rate (mean) | attack sessions deceived (mean) |
|---|---|---|
| 0.0 | 0.0076 | 0.9450 |
| 0.01 | 0.0009 | 0.8581 |
| 0.05 | 0.0000 | 0.1826 |

## Drift: legitimate read rates x1.8 after deployment (alpha = 0.01)

| detector | stale calibration: legit rate | recalibrated on 7 recent days: legit rate | attack deceived (stale / recalibrated) |
|---|---|---|---|
| xgb | 0.0291 | 0.0105 | 0.9150 / 0.8885 |
| iforest | 0.0233 | 0.0109 | 0.4226 / 0.3483 |

## Reading the table

- The guarantee is P(legitimate session ever deceived) <= alpha under exchangeability; the per-role gate makes it hold inside each role.
- 'max over seeds' can exceed alpha by sampling noise because each seed has a finite number of test sessions.
- All numbers are on simulated data written by the same author as the detector; they test the method's mechanics, not real-world performance.
