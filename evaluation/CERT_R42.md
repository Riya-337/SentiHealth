# CERT Insider Threat r4.2, one decision per user-day: measured results

Public synthetic benchmark (CMU SEI). 330,285 user-days (541 malicious, 1000 users), 33 features, 35 role groups. Detectors trained on the first half of the period; mean over 5 seeds. 'Legit deceived' = share of normal user-days put on deception, pooled over seeds with a 95 % Clopper-Pearson interval; 'worst role' averages each role over seeds, then takes the maximum; 'roles above alpha' counts roles significantly above alpha (one-sided binomial test, Holm-corrected, 5 %), summed over seeds. For many decisions per session see CERT_SESSIONS.md.

Detection on the post-training period: xgb ROC-AUC 0.998, PR-AUC 0.895; iforest ROC-AUC 0.893, PR-AUC 0.018.

## Main result: time-ordered calibration (earlier days calibrate, later days evaluate)

**Detector: xgb**

| alpha | per-role: legit deceived [95 % CI] | per-role: worst role | roles above alpha | shared: worst role | roles above alpha | malicious days deceived (per-role) |
|---|---|---|---|---|---|---|
| 0.1 | 9.21 % [9.12 %, 9.30 %] | 20.56 % | 25 / 170 | 36.95 % | 59 / 170 | 99.84 % |
| 0.05 | 4.67 % [4.61 %, 4.74 %] | 15.18 % | 29 / 170 | 22.33 % | 45 / 170 | 99.35 % |
| 0.01 | 1.02 % [0.99 %, 1.05 %] | 6.47 % | 34 / 170 | 4.70 % | 34 / 170 | 96.26 % |
| 0.005 | 0.53 % [0.51 %, 0.56 %] | 5.38 % | 28 / 170 | 2.65 % | 25 / 170 | 94.96 % |

**Detector: iforest**

| alpha | per-role: legit deceived [95 % CI] | per-role: worst role | roles above alpha | shared: worst role | roles above alpha | malicious days deceived (per-role) |
|---|---|---|---|---|---|---|
| 0.1 | 9.21 % [9.12 %, 9.30 %] | 13.48 % | 1 / 170 | 99.51 % | 50 / 170 | 61.95 % |
| 0.05 | 4.57 % [4.50 %, 4.63 %] | 7.60 % | 6 / 170 | 90.00 % | 35 / 170 | 40.65 % |
| 0.01 | 0.83 % [0.81 %, 0.86 %] | 1.35 % | 0 / 170 | 21.84 % | 30 / 170 | 6.83 % |
| 0.005 | 0.40 % [0.38 %, 0.42 %] | 0.92 % | 0 / 170 | 7.54 % | 26 / 170 | 1.63 % |

## Random split of the post-training days

**Detector: xgb**

| alpha | per-role: legit deceived [95 % CI] | per-role: worst role | roles above alpha | shared: worst role | roles above alpha | malicious days deceived (per-role) |
|---|---|---|---|---|---|---|
| 0.1 | 10.04 % [9.94 %, 10.13 %] | 11.36 % | 2 / 171 | 37.60 % | 65 / 171 | 99.65 % |
| 0.05 | 5.02 % [4.95 %, 5.08 %] | 6.42 % | 2 / 171 | 19.59 % | 49 / 171 | 99.11 % |
| 0.01 | 0.97 % [0.94 %, 1.01 %] | 1.32 % | 3 / 171 | 4.38 % | 22 / 171 | 95.67 % |
| 0.005 | 0.47 % [0.45 %, 0.49 %] | 0.72 % | 2 / 171 | 1.93 % | 10 / 171 | 89.76 % |

**Detector: iforest**

| alpha | per-role: legit deceived [95 % CI] | per-role: worst role | roles above alpha | shared: worst role | roles above alpha | malicious days deceived (per-role) |
|---|---|---|---|---|---|---|
| 0.1 | 10.16 % [10.07 %, 10.26 %] | 11.96 % | 4 / 171 | 99.73 % | 55 / 171 | 68.01 % |
| 0.05 | 5.08 % [5.01 %, 5.15 %] | 6.19 % | 6 / 171 | 91.44 % | 36 / 171 | 51.70 % |
| 0.01 | 0.97 % [0.94 %, 1.00 %] | 1.43 % | 5 / 171 | 21.89 % | 32 / 171 | 14.76 % |
| 0.005 | 0.48 % [0.46 %, 0.50 %] | 0.79 % | 2 / 171 | 7.75 % | 25 / 171 | 8.29 % |
