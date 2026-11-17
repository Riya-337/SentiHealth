# CERT Insider Threat r4.2: measured results

Public synthetic benchmark (CMU SEI). 330,285 user-days (541 malicious, 1000 users). Detectors trained on the first half of the period; later user-days split at random into calibration and evaluation; mean over 5 seeds. 'Legit deceived' = share of normal user-days put on deception.

| detector | ROC-AUC | PR-AUC |
|---|---|---|
| xgb | 0.998 | 0.893 |
| iforest | 0.890 | 0.019 |

## Deception gate, detector xgb

| alpha | pooled: legit deceived | pooled: worst role | per-role: legit deceived | per-role: worst role | malicious days deceived (per-role) |
|---|---|---|---|---|---|
| 0.1 | 0.1010 | 0.3760 | 0.1004 | 0.1136 | 0.997 |
| 0.05 | 0.0500 | 0.1959 | 0.0502 | 0.0642 | 0.991 |
| 0.01 | 0.0100 | 0.0438 | 0.0097 | 0.0132 | 0.957 |
| 0.005 | 0.0050 | 0.0193 | 0.0047 | 0.0072 | 0.898 |

Time-ordered calibration, alpha 0.01, per-role: legit deceived 0.0102, malicious days deceived 0.963.

## Deception gate, detector iforest

| alpha | pooled: legit deceived | pooled: worst role | per-role: legit deceived | per-role: worst role | malicious days deceived (per-role) |
|---|---|---|---|---|---|
| 0.1 | 0.1013 | 0.9973 | 0.1016 | 0.1196 | 0.680 |
| 0.05 | 0.0505 | 0.9144 | 0.0508 | 0.0619 | 0.517 |
| 0.01 | 0.0102 | 0.2189 | 0.0097 | 0.0143 | 0.148 |
| 0.005 | 0.0050 | 0.0775 | 0.0048 | 0.0079 | 0.083 |

Time-ordered calibration, alpha 0.01, per-role: legit deceived 0.0083, malicious days deceived 0.068.
