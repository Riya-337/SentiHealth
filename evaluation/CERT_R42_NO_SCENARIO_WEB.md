# CERT Insider Threat r4.2, one decision per user-day: measured results (without http_wikileaks, http_jobsite, http_keylogger)

Public synthetic benchmark (CMU SEI). 330,285 user-days (541 malicious, 1000 users), 30 features, 35 role groups. Detectors trained on the first half of the period; mean over 5 seeds. 'Legit deceived' = share of normal user-days put on deception, pooled over seeds with a 95 % Clopper-Pearson interval; 'worst role' averages each role over seeds, then takes the maximum; 'roles above alpha' counts role-seeds significantly above alpha (Holm-corrected, 5 %), summed over seeds: treating days as independent (binomial test) and, in brackets, with users as clusters (user-level bootstrap, roles with at least 5 users), the count to rely on. For many decisions per session see CERT_SESSIONS.md.

Detection on the post-training period: xgb ROC-AUC 0.998, PR-AUC 0.869; iforest ROC-AUC 0.895, PR-AUC 0.019.

## Main result: time-ordered calibration (earlier days calibrate, later days evaluate)

**Detector: xgb**

| alpha | per-role: legit deceived [95 % CI] | per-role: worst role | roles above alpha | shared: worst role | roles above alpha | malicious days deceived (per-role) |
|---|---|---|---|---|---|---|
| 0.1 | 9.00 % [8.91 %, 9.09 %] | 21.29 % | 21 / 170 (5 / 145) | 38.19 % | 51 / 170 (17 / 145) | 100.00 % |
| 0.05 | 4.62 % [4.55 %, 4.69 %] | 12.21 % | 27 / 170 (4 / 145) | 22.33 % | 38 / 170 (10 / 145) | 99.35 % |
| 0.01 | 0.91 % [0.88 %, 0.94 %] | 5.16 % | 28 / 170 (0 / 145) | 4.50 % | 36 / 170 (3 / 145) | 96.10 % |
| 0.005 | 0.48 % [0.46 %, 0.51 %] | 4.59 % | 26 / 170 (0 / 145) | 2.52 % | 14 / 170 (0 / 145) | 95.12 % |

**Detector: iforest**

| alpha | per-role: legit deceived [95 % CI] | per-role: worst role | roles above alpha | shared: worst role | roles above alpha | malicious days deceived (per-role) |
|---|---|---|---|---|---|---|
| 0.1 | 9.21 % [9.12 %, 9.30 %] | 14.01 % | 7 / 170 (0 / 145) | 99.14 % | 50 / 170 (10 / 145) | 60.49 % |
| 0.05 | 4.54 % [4.47 %, 4.61 %] | 7.42 % | 0 / 170 (0 / 145) | 88.01 % | 35 / 170 (15 / 145) | 41.46 % |
| 0.01 | 0.82 % [0.79 %, 0.85 %] | 1.42 % | 0 / 170 (0 / 145) | 17.60 % | 30 / 170 (3 / 145) | 6.34 % |
| 0.005 | 0.40 % [0.38 %, 0.42 %] | 0.90 % | 0 / 170 (0 / 145) | 7.52 % | 26 / 170 (0 / 145) | 1.79 % |

## Random split of the post-training days

**Detector: xgb**

| alpha | per-role: legit deceived [95 % CI] | per-role: worst role | roles above alpha | shared: worst role | roles above alpha | malicious days deceived (per-role) |
|---|---|---|---|---|---|---|
| 0.1 | 10.05 % [9.96 %, 10.15 %] | 11.55 % | 5 / 171 (0 / 150) | 32.73 % | 58 / 171 (27 / 150) | 99.67 % |
| 0.05 | 5.04 % [4.97 %, 5.11 %] | 6.62 % | 2 / 171 (0 / 150) | 18.41 % | 46 / 171 (11 / 150) | 99.44 % |
| 0.01 | 1.00 % [0.96 %, 1.03 %] | 1.35 % | 3 / 171 (0 / 150) | 3.93 % | 25 / 171 (6 / 150) | 94.87 % |
| 0.005 | 0.47 % [0.45 %, 0.50 %] | 0.71 % | 1 / 171 (0 / 150) | 1.93 % | 16 / 171 (2 / 150) | 88.30 % |

**Detector: iforest**

| alpha | per-role: legit deceived [95 % CI] | per-role: worst role | roles above alpha | shared: worst role | roles above alpha | malicious days deceived (per-role) |
|---|---|---|---|---|---|---|
| 0.1 | 10.13 % [10.04 %, 10.23 %] | 11.74 % | 6 / 171 (0 / 150) | 99.37 % | 55 / 171 (10 / 150) | 68.03 % |
| 0.05 | 5.05 % [4.99 %, 5.12 %] | 5.88 % | 4 / 171 (0 / 150) | 90.88 % | 39 / 171 (10 / 150) | 52.31 % |
| 0.01 | 0.97 % [0.94 %, 1.00 %] | 1.73 % | 5 / 171 (0 / 150) | 17.30 % | 32 / 171 (9 / 150) | 14.89 % |
| 0.005 | 0.48 % [0.46 %, 0.50 %] | 0.87 % | 3 / 171 (0 / 150) | 7.83 % | 27 / 171 (5 / 150) | 7.87 % |
