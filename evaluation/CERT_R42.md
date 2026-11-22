# CERT Insider Threat r4.2, one decision per user-day: measured results

Public synthetic benchmark (CMU SEI). 330,285 user-days (541 malicious, 1000 users), 33 features, 35 role groups. Detectors trained on the first half of the period; mean over 5 seeds. 'Legit deceived' = share of normal user-days put on deception, pooled over seeds with a 95 % Clopper-Pearson interval; 'worst role' averages each role over seeds, then takes the maximum; 'roles above alpha' counts role-seeds significantly above alpha (Holm-corrected, 5 %), summed over seeds: treating days as independent (binomial test) and, in brackets, with users as clusters (user-level bootstrap, roles with at least 5 users), the count to rely on. For many decisions per session see CERT_SESSIONS.md.

Detection on the post-training period: xgb ROC-AUC 0.998, PR-AUC 0.895; iforest ROC-AUC 0.893, PR-AUC 0.018.

## Main result: time-ordered calibration (earlier days calibrate, later days evaluate)

**Detector: xgb**

| alpha | per-role: legit deceived [95 % CI] | per-role: worst role | roles above alpha | shared: worst role | roles above alpha | malicious days deceived (per-role) |
|---|---|---|---|---|---|---|
| 0.1 | 9.21 % [9.12 %, 9.30 %] | 20.56 % | 25 / 170 (5 / 145) | 36.95 % | 59 / 170 (29 / 145) | 99.84 % |
| 0.05 | 4.67 % [4.61 %, 4.74 %] | 15.18 % | 29 / 170 (6 / 145) | 22.33 % | 45 / 170 (11 / 145) | 99.35 % |
| 0.01 | 1.02 % [0.99 %, 1.05 %] | 6.47 % | 34 / 170 (0 / 145) | 4.70 % | 34 / 170 (1 / 145) | 96.26 % |
| 0.005 | 0.53 % [0.51 %, 0.56 %] | 5.38 % | 28 / 170 (0 / 145) | 2.65 % | 25 / 170 (0 / 145) | 94.96 % |

**Detector: iforest**

| alpha | per-role: legit deceived [95 % CI] | per-role: worst role | roles above alpha | shared: worst role | roles above alpha | malicious days deceived (per-role) |
|---|---|---|---|---|---|---|
| 0.1 | 9.21 % [9.12 %, 9.30 %] | 13.48 % | 1 / 170 (0 / 145) | 99.51 % | 50 / 170 (10 / 145) | 61.95 % |
| 0.05 | 4.57 % [4.50 %, 4.63 %] | 7.60 % | 6 / 170 (0 / 145) | 90.00 % | 35 / 170 (11 / 145) | 40.65 % |
| 0.01 | 0.83 % [0.81 %, 0.86 %] | 1.35 % | 0 / 170 (0 / 145) | 21.84 % | 30 / 170 (5 / 145) | 6.83 % |
| 0.005 | 0.40 % [0.38 %, 0.42 %] | 0.92 % | 0 / 170 (0 / 145) | 7.54 % | 26 / 170 (0 / 145) | 1.63 % |

## Random split of the post-training days

**Detector: xgb**

| alpha | per-role: legit deceived [95 % CI] | per-role: worst role | roles above alpha | shared: worst role | roles above alpha | malicious days deceived (per-role) |
|---|---|---|---|---|---|---|
| 0.1 | 10.04 % [9.94 %, 10.13 %] | 11.36 % | 2 / 171 (0 / 150) | 37.60 % | 65 / 171 (33 / 150) | 99.65 % |
| 0.05 | 5.02 % [4.95 %, 5.08 %] | 6.42 % | 2 / 171 (0 / 150) | 19.59 % | 49 / 171 (16 / 150) | 99.11 % |
| 0.01 | 0.97 % [0.94 %, 1.01 %] | 1.32 % | 3 / 171 (0 / 150) | 4.38 % | 22 / 171 (5 / 150) | 95.67 % |
| 0.005 | 0.47 % [0.45 %, 0.49 %] | 0.72 % | 2 / 171 (0 / 150) | 1.93 % | 10 / 171 (2 / 150) | 89.76 % |

**Detector: iforest**

| alpha | per-role: legit deceived [95 % CI] | per-role: worst role | roles above alpha | shared: worst role | roles above alpha | malicious days deceived (per-role) |
|---|---|---|---|---|---|---|
| 0.1 | 10.16 % [10.07 %, 10.26 %] | 11.96 % | 4 / 171 (0 / 150) | 99.73 % | 55 / 171 (10 / 150) | 68.01 % |
| 0.05 | 5.08 % [5.01 %, 5.15 %] | 6.19 % | 6 / 171 (0 / 150) | 91.44 % | 36 / 171 (10 / 150) | 51.70 % |
| 0.01 | 0.97 % [0.94 %, 1.00 %] | 1.43 % | 5 / 171 (0 / 150) | 21.89 % | 32 / 171 (10 / 150) | 14.76 % |
| 0.005 | 0.48 % [0.46 %, 0.50 %] | 0.79 % | 2 / 171 (0 / 150) | 7.75 % | 25 / 171 (5 / 150) | 8.29 % |
