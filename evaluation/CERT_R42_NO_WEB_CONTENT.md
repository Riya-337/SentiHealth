# CERT Insider Threat r4.2: measured results (without http_wikileaks, http_jobsite, http_keylogger, http_cloud)

Public synthetic benchmark (CMU SEI). 330,285 user-days (541 malicious, 1000 users), 29 features. Detectors trained on the first half of the period; later user-days split at random into calibration and evaluation; mean over 5 seeds. 'Legit deceived' = share of normal user-days put on deception.

| detector | ROC-AUC | PR-AUC |
|---|---|---|
| xgb | 0.998 | 0.864 |
| iforest | 0.893 | 0.022 |

## Deception gate, detector xgb

| alpha | pooled: legit deceived | pooled: worst role | per-role: legit deceived | per-role: worst role | malicious days deceived (per-role) |
|---|---|---|---|---|---|
| 0.1 | 0.1009 | 0.3413 | 0.1005 | 0.1142 | 0.999 |
| 0.05 | 0.0509 | 0.1780 | 0.0506 | 0.0629 | 0.989 |
| 0.01 | 0.0099 | 0.0369 | 0.0099 | 0.0120 | 0.952 |
| 0.005 | 0.0050 | 0.0193 | 0.0049 | 0.0079 | 0.882 |

Time-ordered calibration, alpha 0.01, per-role: legit deceived 0.0093, malicious days deceived 0.956.

## Deception gate, detector iforest

| alpha | pooled: legit deceived | pooled: worst role | per-role: legit deceived | per-role: worst role | malicious days deceived (per-role) |
|---|---|---|---|---|---|
| 0.1 | 0.1013 | 0.9957 | 0.1017 | 0.1191 | 0.691 |
| 0.05 | 0.0505 | 0.9200 | 0.0507 | 0.0578 | 0.531 |
| 0.01 | 0.0100 | 0.1707 | 0.0098 | 0.0147 | 0.163 |
| 0.005 | 0.0050 | 0.0808 | 0.0047 | 0.0085 | 0.079 |

Time-ordered calibration, alpha 0.01, per-role: legit deceived 0.0081, malicious days deceived 0.081.
