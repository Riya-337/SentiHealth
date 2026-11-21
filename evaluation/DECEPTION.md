# Deception with a safety guarantee: measured results

Generated 2026-11-21T15:59:01+00:00. **Synthetic data** (ml/simulate_events.py), 5 seeds, 28 days, 300 users per seed. A session is ever deceived if the gate put it on noise or decoys at any event. Rates are pooled over seeds with a 95 % Clopper-Pearson interval; 'worst role' averages each role's rate over seeds, then takes the maximum; 'roles above alpha' counts roles whose rate is significantly above alpha (one-sided binomial test, Holm-corrected over roles, 5 %), summed over seeds.

## Main result: time-ordered calibration

Detectors are trained on the first half of the period. Within the rest, earlier sessions calibrate the gate and later sessions evaluate it, as a deployment would.

**Detector: xgb**

| alpha | per-role gate: legit deceived [95 % CI] | worst role | roles above alpha | shared threshold: worst role | roles above alpha | attack sessions deceived | attacker reads on decoys |
|---|---|---|---|---|---|---|---|
| 0.1 | 9.66 % [9.00 %, 10.35 %] | 11.33 % | 0 / 25 | 12.37 % | 5 / 25 | 97.21 % | 98.37 % |
| 0.05 | 5.04 % [4.55 %, 5.56 %] | 6.79 % | 0 / 25 | 7.48 % | 4 / 25 | 96.10 % | 95.92 % |
| 0.02 | 2.25 % [1.93 %, 2.61 %] | 2.80 % | 1 / 25 | 4.66 % | 4 / 25 | 95.44 % | 74.54 % |
| 0.01 | 1.19 % [0.95 %, 1.46 %] | 1.98 % | 2 / 25 | 2.54 % | 0 / 25 | 94.34 % | 51.63 % |
| 0.005 | 0.37 % [0.25 %, 0.54 %] | 0.92 % | 1 / 25 | 1.35 % | 2 / 25 | 78.69 % | 0.00 % |

**Detector: iforest**

| alpha | per-role gate: legit deceived [95 % CI] | worst role | roles above alpha | shared threshold: worst role | roles above alpha | attack sessions deceived | attacker reads on decoys |
|---|---|---|---|---|---|---|---|
| 0.1 | 10.05 % [9.37 %, 10.75 %] | 12.09 % | 2 / 25 | 15.93 % | 4 / 25 | 83.53 % | 82.02 % |
| 0.05 | 5.18 % [4.69 %, 5.71 %] | 6.81 % | 2 / 25 | 7.23 % | 2 / 25 | 81.01 % | 76.78 % |
| 0.02 | 1.96 % [1.66 %, 2.30 %] | 2.55 % | 0 / 25 | 2.46 % | 0 / 25 | 53.89 % | 63.80 % |
| 0.01 | 1.03 % [0.81 %, 1.28 %] | 1.44 % | 2 / 25 | 1.49 % | 1 / 25 | 44.81 % | 46.91 % |
| 0.005 | 0.31 % [0.19 %, 0.46 %] | 0.52 % | 0 / 25 | 0.52 % | 0 / 25 | 30.70 % | 0.00 % |

## Random split (exchangeable setting assumed by the theory)

**Detector: xgb**

| alpha | per-role gate: legit deceived [95 % CI] | worst role | roles above alpha | shared threshold: worst role | roles above alpha | attack sessions deceived | attacker reads on decoys |
|---|---|---|---|---|---|---|---|
| 0.1 | 9.87 % [9.21 %, 10.57 %] | 10.13 % | 1 / 25 | 12.60 % | 3 / 25 | 97.57 % | 98.62 % |
| 0.05 | 4.80 % [4.32 %, 5.30 %] | 4.99 % | 0 / 25 | 7.54 % | 2 / 25 | 96.87 % | 96.72 % |
| 0.02 | 1.77 % [1.49 %, 2.10 %] | 2.25 % | 0 / 25 | 4.02 % | 2 / 25 | 95.86 % | 64.91 % |
| 0.01 | 0.67 % [0.49 %, 0.88 %] | 1.49 % | 1 / 25 | 1.74 % | 1 / 25 | 92.68 % | 39.58 % |
| 0.005 | 0.19 % [0.10 %, 0.31 %] | 0.53 % | 1 / 25 | 0.93 % | 0 / 25 | 75.97 % | 0.00 % |

**Detector: iforest**

| alpha | per-role gate: legit deceived [95 % CI] | worst role | roles above alpha | shared threshold: worst role | roles above alpha | attack sessions deceived | attacker reads on decoys |
|---|---|---|---|---|---|---|---|
| 0.1 | 10.13 % [9.45 %, 10.83 %] | 11.15 % | 0 / 25 | 16.24 % | 5 / 25 | 83.79 % | 82.14 % |
| 0.05 | 4.76 % [4.29 %, 5.26 %] | 5.22 % | 0 / 25 | 8.13 % | 2 / 25 | 80.72 % | 73.06 % |
| 0.02 | 1.68 % [1.40 %, 2.00 %] | 2.04 % | 0 / 25 | 2.72 % | 0 / 25 | 51.37 % | 47.98 % |
| 0.01 | 0.89 % [0.69 %, 1.13 %] | 1.03 % | 0 / 25 | 1.14 % | 0 / 25 | 44.62 % | 29.44 % |
| 0.005 | 0.21 % [0.12 %, 0.35 %] | 0.30 % | 0 / 25 | 0.57 % | 0 / 25 | 28.43 % | 0.00 % |

## Baselines (time-ordered calibration)

All rules use the same running-maximum decision; only the threshold differs. *Per-event conformal* calibrates on individual event scores (as conformal false-positive control for alert gating does) instead of whole-session maxima. *Per-role quantile* uses each role's empirical (1 - alpha) quantile without the finite-sample correction. *Per-role Neyman-Pearson* (umbrella algorithm, delta = 0.05) bounds the rate with probability 0.95 over the calibration draw.

| detector | alpha | rule | legit deceived | worst role | roles above alpha | attack sessions deceived |
|---|---|---|---|---|---|---|
| xgb | 0.1 | shared conformal | 9.75 % | 12.37 % | 5 / 25 | 97.31 % |
| xgb | 0.1 | **per-role conformal (ours)** | 9.66 % | 11.33 % | 0 / 25 | 97.21 % |
| xgb | 0.1 | per event conformal | 98.21 % | 99.27 % | 25 / 25 | 99.90 % |
| xgb | 0.1 | per role quantile | 9.98 % | 11.70 % | 0 / 25 | 97.21 % |
| xgb | 0.1 | per role neyman pearson | 7.54 % | 7.86 % | 0 / 25 | 97.21 % |
| xgb | 0.05 | shared conformal | 5.22 % | 7.48 % | 4 / 25 | 96.00 % |
| xgb | 0.05 | **per-role conformal (ours)** | 5.04 % | 6.79 % | 0 / 25 | 96.10 % |
| xgb | 0.05 | per event conformal | 92.57 % | 95.96 % | 25 / 25 | 99.90 % |
| xgb | 0.05 | per role quantile | 5.44 % | 7.60 % | 1 / 25 | 96.20 % |
| xgb | 0.05 | per role neyman pearson | 3.13 % | 3.34 % | 0 / 25 | 95.89 % |
| xgb | 0.02 | shared conformal | 2.36 % | 4.66 % | 4 / 25 | 95.02 % |
| xgb | 0.02 | **per-role conformal (ours)** | 2.25 % | 2.80 % | 1 / 25 | 95.44 % |
| xgb | 0.02 | per event conformal | 77.42 % | 85.37 % | 25 / 25 | 99.80 % |
| xgb | 0.02 | per role quantile | 2.50 % | 2.95 % | 1 / 25 | 95.44 % |
| xgb | 0.02 | per role neyman pearson | 1.17 % | 1.70 % | 1 / 25 | 89.34 % |
| xgb | 0.01 | shared conformal | 1.13 % | 2.54 % | 0 / 25 | 93.63 % |
| xgb | 0.01 | **per-role conformal (ours)** | 1.19 % | 1.98 % | 2 / 25 | 94.34 % |
| xgb | 0.01 | per event conformal | 60.72 % | 69.77 % | 25 / 25 | 99.71 % |
| xgb | 0.01 | per role quantile | 1.65 % | 2.43 % | 3 / 25 | 94.83 % |
| xgb | 0.01 | per role neyman pearson | 0.19 % | 0.31 % | 0 / 25 | 65.44 % |
| xgb | 0.005 | shared conformal | 0.61 % | 1.35 % | 2 / 25 | 91.78 % |
| xgb | 0.005 | **per-role conformal (ours)** | 0.37 % | 0.92 % | 1 / 25 | 78.69 % |
| xgb | 0.005 | per event conformal | 42.47 % | 49.67 % | 25 / 25 | 99.40 % |
| xgb | 0.005 | per role quantile | 1.07 % | 1.98 % | 5 / 25 | 94.19 % |
| xgb | 0.005 | per role neyman pearson | 0.01 % | 0.03 % | 0 / 25 | 39.02 % |
| iforest | 0.1 | shared conformal | 10.10 % | 15.93 % | 4 / 25 | 83.35 % |
| iforest | 0.1 | **per-role conformal (ours)** | 10.05 % | 12.09 % | 2 / 25 | 83.53 % |
| iforest | 0.1 | per event conformal | 94.38 % | 97.96 % | 25 / 25 | 99.63 % |
| iforest | 0.1 | per role quantile | 10.34 % | 12.54 % | 2 / 25 | 83.53 % |
| iforest | 0.1 | per role neyman pearson | 7.73 % | 9.59 % | 1 / 25 | 82.34 % |
| iforest | 0.05 | shared conformal | 5.16 % | 7.23 % | 2 / 25 | 80.96 % |
| iforest | 0.05 | **per-role conformal (ours)** | 5.18 % | 6.81 % | 2 / 25 | 81.01 % |
| iforest | 0.05 | per event conformal | 80.30 % | 90.81 % | 25 / 25 | 99.53 % |
| iforest | 0.05 | per role quantile | 5.57 % | 7.90 % | 2 / 25 | 81.37 % |
| iforest | 0.05 | per role neyman pearson | 3.41 % | 4.11 % | 0 / 25 | 79.20 % |
| iforest | 0.02 | shared conformal | 2.08 % | 2.46 % | 0 / 25 | 55.21 % |
| iforest | 0.02 | **per-role conformal (ours)** | 1.96 % | 2.55 % | 0 / 25 | 53.89 % |
| iforest | 0.02 | per event conformal | 58.65 % | 74.26 % | 25 / 25 | 98.02 % |
| iforest | 0.02 | per role quantile | 2.65 % | 3.78 % | 4 / 25 | 57.69 % |
| iforest | 0.02 | per role neyman pearson | 0.95 % | 1.51 % | 0 / 25 | 42.62 % |
| iforest | 0.01 | shared conformal | 1.04 % | 1.49 % | 1 / 25 | 45.77 % |
| iforest | 0.01 | **per-role conformal (ours)** | 1.03 % | 1.44 % | 2 / 25 | 44.81 % |
| iforest | 0.01 | per event conformal | 43.47 % | 58.75 % | 25 / 25 | 95.34 % |
| iforest | 0.01 | per role quantile | 1.43 % | 2.05 % | 2 / 25 | 48.01 % |
| iforest | 0.01 | per role neyman pearson | 0.23 % | 0.52 % | 0 / 25 | 21.74 % |
| iforest | 0.005 | shared conformal | 0.37 % | 0.52 % | 0 / 25 | 36.73 % |
| iforest | 0.005 | **per-role conformal (ours)** | 0.31 % | 0.52 % | 0 / 25 | 30.70 % |
| iforest | 0.005 | per event conformal | 27.24 % | 40.00 % | 25 / 25 | 90.17 % |
| iforest | 0.005 | per role quantile | 0.89 % | 1.46 % | 4 / 25 | 43.44 % |
| iforest | 0.005 | per role neyman pearson | 0.11 % | 0.23 % | 0 / 25 | 11.14 % |

## Fixed threshold on the detector's probability (no guarantee)

| threshold | legit deceived | worst role | attack sessions deceived |
|---|---|---|---|
| 0.5 | 0.48 % | 1.13 % | 92.63 % |
| 0.75 | 0.29 % | 0.80 % | 91.29 % |
| 0.9 | 0.17 % | 0.48 % | 89.75 % |

## Contaminated calibration (alpha = 0.01, shared threshold, time-ordered)

Attack sessions mislabelled as legitimate, as a share of the legitimate calibration sessions. *Random*: any attack session (mostly detected, high-scoring ones). *Stealthiest*: the lowest-scoring attack sessions, the ones most likely to go unnoticed and be mislabelled in practice.

| detector | contamination | share added | legit deceived [95 % CI] | attack sessions deceived |
|---|---|---|---|---|
| xgb | random | 0.0 | 1.13 % [0.91 %, 1.40 %] | 93.63 % |
| xgb | random | 0.01 | 0.08 % [0.03 %, 0.17 %] | 84.27 % |
| xgb | random | 0.05 | 0.00 % [0.00 %, 0.05 %] | 20.16 % |
| xgb | stealthiest | 0.0 | 1.13 % [0.91 %, 1.40 %] | 93.63 % |
| xgb | stealthiest | 0.01 | 0.93 % [0.73 %, 1.18 %] | 93.40 % |
| xgb | stealthiest | 0.05 | 0.00 % [0.00 %, 0.05 %] | 63.67 % |
| iforest | random | 0.0 | 1.04 % [0.82 %, 1.30 %] | 45.77 % |
| iforest | random | 0.01 | 0.52 % [0.37 %, 0.71 %] | 39.76 % |
| iforest | random | 0.05 | 0.04 % [0.01 %, 0.12 %] | 19.97 % |
| iforest | stealthiest | 0.0 | 1.04 % [0.82 %, 1.30 %] | 45.77 % |
| iforest | stealthiest | 0.01 | 1.05 % [0.83 %, 1.31 %] | 45.77 % |
| iforest | stealthiest | 0.05 | 1.08 % [0.86 %, 1.34 %] | 45.77 % |

## Drift: legitimate read rates x1.8 after deployment (alpha = 0.01)

| detector | stale calibration: legit deceived | recalibrated on 7 recent days | attack deceived (stale / recalibrated) |
|---|---|---|---|
| xgb | 2.91 % | 1.05 % | 91.50 % / 88.85 % |
| iforest | 2.34 % | 1.09 % | 42.26 % / 34.83 % |

## Reading the tables

- The guarantee is P(legitimate session ever deceived) <= alpha under exchangeability; the per-role gate makes it hold inside each role.
- The worst role is the maximum over several noisy estimates, so it can sit above alpha by chance; 'roles above alpha' tests whether any role is significantly above it.
- Contamination is conservative only when the mislabelled sessions score above the clean threshold; low-scoring (stealthy) attacks can lower it.
- All numbers are on simulated data written by the same author as the detector; they test the method's mechanics, not real-world performance.
