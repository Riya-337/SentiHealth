# CERT r4.2 sessions: the deception gate on real event sequences

Public synthetic benchmark (CMU SEI). 4,133,758 logon, USB, file and e-mail events from 1,000 users, grouped into 1,438,507 sessions (no gap over 30 min), 1,540 of them containing malicious events; 39 role groups. The gate re-decides at every event; a session counts as deceived if it was deceived at any event. Mean of 5 seeds. Rates are pooled over seeds with a 95 % Clopper-Pearson interval; 'worst role' averages each role over seeds, then takes the maximum; 'roles above alpha' counts roles significantly above alpha (one-sided binomial test, Holm-corrected, 5 %), summed over seeds.

Session-level detection on the post-training period (session maximum score): xgb ROC-AUC 0.920, PR-AUC 0.213; iforest ROC-AUC 0.706, PR-AUC 0.003.

## Main result: time-ordered calibration

**Detector: xgb**

| alpha | per-role gate: legit sessions deceived [95 % CI] | worst role | roles above alpha | shared threshold: worst role | roles above alpha | malicious sessions deceived | malicious events after deception |
|---|---|---|---|---|---|---|---|
| 0.1 | 9.72 % [9.67 %, 9.76 %] | 27.53 % | 52 / 195 | 61.85 % | 71 / 195 | 89.25 % | 90.27 % |
| 0.05 | 4.85 % [4.82 %, 4.88 %] | 18.09 % | 59 / 195 | 40.55 % | 57 / 195 | 86.26 % | 86.54 % |
| 0.01 | 1.01 % [1.00 %, 1.03 %] | 6.68 % | 61 / 195 | 8.48 % | 34 / 195 | 66.32 % | 63.93 % |
| 0.005 | 0.54 % [0.53 %, 0.55 %] | 4.20 % | 54 / 195 | 2.04 % | 24 / 195 | 57.73 % | 55.42 % |

**Detector: iforest**

| alpha | per-role gate: legit sessions deceived [95 % CI] | worst role | roles above alpha | shared threshold: worst role | roles above alpha | malicious sessions deceived | malicious events after deception |
|---|---|---|---|---|---|---|---|
| 0.1 | 9.67 % [9.63 %, 9.72 %] | 12.56 % | 4 / 195 | 51.25 % | 65 / 195 | 22.88 % | 19.47 % |
| 0.05 | 4.85 % [4.82 %, 4.89 %] | 5.98 % | 0 / 195 | 29.46 % | 61 / 195 | 12.74 % | 11.98 % |
| 0.01 | 0.96 % [0.94 %, 0.97 %] | 1.48 % | 0 / 195 | 13.42 % | 52 / 195 | 3.43 % | 3.15 % |
| 0.005 | 0.47 % [0.46 %, 0.48 %] | 0.87 % | 1 / 195 | 9.20 % | 49 / 195 | 1.94 % | 1.60 % |

## Random split (exchangeable setting)

**Detector: xgb**

| alpha | per-role gate: legit sessions deceived [95 % CI] | worst role | roles above alpha | shared threshold: worst role | roles above alpha | malicious sessions deceived | malicious events after deception |
|---|---|---|---|---|---|---|---|
| 0.1 | 10.02 % [9.98 %, 10.07 %] | 11.10 % | 3 / 195 | 60.14 % | 72 / 195 | 78.60 % | 77.95 % |
| 0.05 | 5.02 % [4.99 %, 5.06 %] | 5.70 % | 4 / 195 | 37.31 % | 51 / 195 | 74.59 % | 73.19 % |
| 0.01 | 1.01 % [0.99 %, 1.02 %] | 1.22 % | 4 / 195 | 10.31 % | 45 / 195 | 57.59 % | 55.33 % |
| 0.005 | 0.50 % [0.49 %, 0.51 %] | 0.64 % | 1 / 195 | 4.19 % | 45 / 195 | 49.50 % | 47.25 % |

**Detector: iforest**

| alpha | per-role gate: legit sessions deceived [95 % CI] | worst role | roles above alpha | shared threshold: worst role | roles above alpha | malicious sessions deceived | malicious events after deception |
|---|---|---|---|---|---|---|---|
| 0.1 | 9.93 % [9.89 %, 9.98 %] | 11.11 % | 3 / 195 | 51.07 % | 61 / 195 | 26.32 % | 21.62 % |
| 0.05 | 4.98 % [4.94 %, 5.01 %] | 5.79 % | 5 / 195 | 29.79 % | 57 / 195 | 13.68 % | 12.08 % |
| 0.01 | 0.99 % [0.98 %, 1.01 %] | 1.17 % | 2 / 195 | 13.24 % | 53 / 195 | 3.55 % | 2.43 % |
| 0.005 | 0.50 % [0.49 %, 0.51 %] | 0.76 % | 6 / 195 | 9.14 % | 47 / 195 | 1.77 % | 1.00 % |

## Drift and rolling recalibration

*Static*: the time-ordered gate above (calibrated once), its legitimate-session rate in each evaluation month. *Rolling*: before each evaluation month the gate is recalibrated on the legitimate sessions of the previous 60 days.

**Detector: xgb**

| alpha | static per-role gate, by month (2011-01, 2011-02, 2011-03, 2011-04, 2011-05) | rolling per-role: legit deceived [95 % CI] | worst role | roles above alpha | rolling shared: worst role | roles above alpha | malicious sessions deceived (rolling per-role) |
|---|---|---|---|---|---|---|---|
| 0.1 | 8.90 % / 9.90 % / 10.05 % / 9.45 % / 10.32 % | 10.16 % [10.11 %, 10.20 %] | 24.14 % | 65 / 195 | 62.99 % | 73 / 195 | 89.36 % |
| 0.05 | 4.41 % / 4.92 % / 5.04 % / 4.78 % / 5.04 % | 5.26 % [5.22 %, 5.29 %] | 17.01 % | 78 / 195 | 41.90 % | 62 / 195 | 86.65 % |
| 0.01 | 0.93 % / 1.08 % / 0.92 % / 1.01 % / 1.19 % | 1.19 % [1.18 %, 1.21 %] | 7.48 % | 103 / 195 | 11.37 % | 35 / 195 | 62.05 % |
| 0.005 | 0.52 % / 0.56 % / 0.47 % / 0.54 % / 0.69 % | 0.68 % [0.67 %, 0.69 %] | 4.57 % | 95 / 195 | 3.54 % | 31 / 195 | 55.57 % |

**Detector: iforest**

| alpha | static per-role gate, by month (2011-01, 2011-02, 2011-03, 2011-04, 2011-05) | rolling per-role: legit deceived [95 % CI] | worst role | roles above alpha | rolling shared: worst role | roles above alpha | malicious sessions deceived (rolling per-role) |
|---|---|---|---|---|---|---|---|
| 0.1 | 9.65 % / 9.56 % / 9.35 % / 10.08 % / 9.88 % | 9.87 % [9.82 %, 9.91 %] | 11.90 % | 0 / 195 | 52.38 % | 67 / 195 | 22.38 % |
| 0.05 | 4.81 % / 4.83 % / 4.61 % / 5.10 % / 5.03 % | 4.94 % [4.91 %, 4.97 %] | 5.64 % | 0 / 195 | 29.89 % | 63 / 195 | 12.63 % |
| 0.01 | 0.99 % / 0.92 % / 0.91 % / 1.01 % / 0.97 % | 0.96 % [0.95 %, 0.98 %] | 1.12 % | 0 / 195 | 13.49 % | 53 / 195 | 3.55 % |
| 0.005 | 0.49 % / 0.46 % / 0.46 % / 0.49 % / 0.46 % | 0.48 % [0.47 %, 0.49 %] | 0.73 % | 0 / 195 | 9.13 % | 49 / 195 | 1.88 % |

## Baselines (time-ordered calibration)

Same running-maximum decision for every rule; only the threshold differs. *Per-event conformal* calibrates on individual event scores instead of whole-session maxima. *Per-role quantile*: empirical (1 - alpha) quantile per role, no finite-sample correction. *Per-role Neyman-Pearson*: umbrella algorithm, delta = 0.05.

| detector | alpha | rule | legit sessions deceived | worst role | roles above alpha | malicious sessions deceived |
|---|---|---|---|---|---|---|
| xgb | 0.1 | shared conformal | 9.67 % | 61.85 % | 71 / 195 | 90.69 % |
| xgb | 0.1 | **per-role conformal (ours)** | 9.72 % | 27.53 % | 52 / 195 | 89.25 % |
| xgb | 0.1 | per event conformal | 17.64 % | 78.20 % | 148 / 195 | 92.35 % |
| xgb | 0.1 | per role quantile | 9.74 % | 27.74 % | 54 / 195 | 89.25 % |
| xgb | 0.1 | per role neyman pearson | 9.31 % | 25.15 % | 42 / 195 | 88.92 % |
| xgb | 0.05 | shared conformal | 4.66 % | 40.55 % | 57 / 195 | 86.93 % |
| xgb | 0.05 | **per-role conformal (ours)** | 4.85 % | 18.09 % | 59 / 195 | 86.26 % |
| xgb | 0.05 | per event conformal | 8.65 % | 58.30 % | 120 / 195 | 90.14 % |
| xgb | 0.05 | per role quantile | 4.87 % | 18.20 % | 63 / 195 | 86.32 % |
| xgb | 0.05 | per role neyman pearson | 4.56 % | 16.50 % | 42 / 195 | 85.98 % |
| xgb | 0.01 | shared conformal | 0.77 % | 8.48 % | 34 / 195 | 68.37 % |
| xgb | 0.01 | **per-role conformal (ours)** | 1.01 % | 6.68 % | 61 / 195 | 66.32 % |
| xgb | 0.01 | per event conformal | 1.39 % | 16.11 % | 63 / 195 | 75.24 % |
| xgb | 0.01 | per role quantile | 1.03 % | 7.76 % | 61 / 195 | 66.48 % |
| xgb | 0.01 | per role neyman pearson | 0.87 % | 4.20 % | 45 / 195 | 64.16 % |
| xgb | 0.005 | shared conformal | 0.32 % | 2.04 % | 24 / 195 | 58.84 % |
| xgb | 0.005 | **per-role conformal (ours)** | 0.54 % | 4.20 % | 54 / 195 | 57.73 % |
| xgb | 0.005 | per event conformal | 0.59 % | 5.34 % | 44 / 195 | 65.48 % |
| xgb | 0.005 | per role quantile | 0.56 % | 5.17 % | 56 / 195 | 58.39 % |
| xgb | 0.005 | per role neyman pearson | 0.44 % | 2.43 % | 34 / 195 | 54.57 % |
| iforest | 0.1 | shared conformal | 9.68 % | 51.25 % | 65 / 195 | 16.45 % |
| iforest | 0.1 | **per-role conformal (ours)** | 9.67 % | 12.56 % | 4 / 195 | 22.88 % |
| iforest | 0.1 | per event conformal | 5.42 % | 32.07 % | 28 / 195 | 10.19 % |
| iforest | 0.1 | per role quantile | 9.69 % | 12.85 % | 4 / 195 | 22.88 % |
| iforest | 0.1 | per role neyman pearson | 9.23 % | 10.51 % | 0 / 195 | 22.33 % |
| iforest | 0.05 | shared conformal | 4.82 % | 29.46 % | 61 / 195 | 9.36 % |
| iforest | 0.05 | **per-role conformal (ours)** | 4.85 % | 5.98 % | 0 / 195 | 12.74 % |
| iforest | 0.05 | per event conformal | 2.56 % | 20.59 % | 33 / 195 | 5.98 % |
| iforest | 0.05 | per role quantile | 4.87 % | 6.59 % | 0 / 195 | 12.74 % |
| iforest | 0.05 | per role neyman pearson | 4.53 % | 5.19 % | 0 / 195 | 12.19 % |
| iforest | 0.01 | shared conformal | 0.99 % | 13.42 % | 52 / 195 | 1.55 % |
| iforest | 0.01 | **per-role conformal (ours)** | 0.96 % | 1.48 % | 0 / 195 | 3.43 % |
| iforest | 0.01 | per event conformal | 0.51 % | 9.36 % | 33 / 195 | 0.50 % |
| iforest | 0.01 | per role quantile | 0.97 % | 1.93 % | 1 / 195 | 3.43 % |
| iforest | 0.01 | per role neyman pearson | 0.82 % | 1.18 % | 0 / 195 | 3.27 % |
| iforest | 0.005 | shared conformal | 0.50 % | 9.20 % | 49 / 195 | 0.50 % |
| iforest | 0.005 | **per-role conformal (ours)** | 0.47 % | 0.87 % | 1 / 195 | 1.94 % |
| iforest | 0.005 | per event conformal | 0.25 % | 5.89 % | 28 / 195 | 0.22 % |
| iforest | 0.005 | per role quantile | 0.49 % | 1.22 % | 2 / 195 | 1.94 % |
| iforest | 0.005 | per role neyman pearson | 0.38 % | 0.74 % | 0 / 195 | 1.61 % |

## Contaminated calibration (alpha = 0.01, shared threshold, time-ordered)

Malicious sessions mislabelled as legitimate, as a share of the legitimate calibration sessions. *Random*: any malicious session. *Stealthiest*: the lowest-scoring ones, the most likely to go unnoticed.

| detector | contamination | share added | legit sessions deceived [95 % CI] | malicious sessions deceived |
|---|---|---|---|---|
| xgb | random | 0.0 | 0.77 % [0.75 %, 0.78 %] | 68.37 % |
| xgb | random | 0.01 | 0.68 % [0.67 %, 0.69 %] | 66.87 % |
| xgb | random | 0.05 | 0.68 % [0.67 %, 0.69 %] | 66.87 % |
| xgb | stealthiest | 0.0 | 0.77 % [0.75 %, 0.78 %] | 68.37 % |
| xgb | stealthiest | 0.01 | 0.68 % [0.67 %, 0.69 %] | 66.87 % |
| xgb | stealthiest | 0.05 | 0.68 % [0.67 %, 0.69 %] | 66.87 % |
| iforest | random | 0.0 | 0.99 % [0.97 %, 1.00 %] | 1.55 % |
| iforest | random | 0.01 | 0.98 % [0.97 %, 1.00 %] | 1.55 % |
| iforest | random | 0.05 | 0.98 % [0.97 %, 1.00 %] | 1.55 % |
| iforest | stealthiest | 0.0 | 0.99 % [0.97 %, 1.00 %] | 1.55 % |
| iforest | stealthiest | 0.01 | 0.98 % [0.97 %, 1.00 %] | 1.55 % |
| iforest | stealthiest | 0.05 | 0.98 % [0.97 %, 1.00 %] | 1.55 % |

## Limits

- CERT r4.2 is synthetic (generated enterprise activity), not hospital EHR logs.
- Web browsing is not in the sessions (CERT's event-level web log is not stored here), so scenario steps that happen only on the web are not seen.
- Role groups come from the monthly LDAP snapshots; roles with few sessions share one group.
