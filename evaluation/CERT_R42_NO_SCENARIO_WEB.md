# CERT Insider Threat r4.2: measured results (without http_wikileaks, http_jobsite, http_keylogger)

Public synthetic benchmark (CMU SEI). 330,285 user-days (541 malicious, 1000 users), 30 features. Detectors trained on the first half of the period; later user-days split at random into calibration and evaluation; mean over 5 seeds. 'Legit deceived' = share of normal user-days put on deception.

| detector | ROC-AUC | PR-AUC |
|---|---|---|
| xgb | 0.998 | 0.865 |
| iforest | 0.892 | 0.021 |

## Deception gate, detector xgb

| alpha | pooled: legit deceived | pooled: worst role | per-role: legit deceived | per-role: worst role | malicious days deceived (per-role) |
|---|---|---|---|---|---|
| 0.1 | 0.1013 | 0.3273 | 0.1005 | 0.1155 | 0.997 |
| 0.05 | 0.0512 | 0.1841 | 0.0504 | 0.0662 | 0.994 |
| 0.01 | 0.0101 | 0.0393 | 0.0100 | 0.0135 | 0.949 |
| 0.005 | 0.0050 | 0.0193 | 0.0047 | 0.0071 | 0.883 |

Time-ordered calibration, alpha 0.01, per-role: legit deceived 0.0091, malicious days deceived 0.961.

## Deception gate, detector iforest

| alpha | pooled: legit deceived | pooled: worst role | per-role: legit deceived | per-role: worst role | malicious days deceived (per-role) |
|---|---|---|---|---|---|
| 0.1 | 0.1011 | 0.9937 | 0.1013 | 0.1174 | 0.680 |
| 0.05 | 0.0505 | 0.9088 | 0.0505 | 0.0588 | 0.523 |
| 0.01 | 0.0100 | 0.1730 | 0.0097 | 0.0173 | 0.149 |
| 0.005 | 0.0050 | 0.0783 | 0.0048 | 0.0087 | 0.079 |

Time-ordered calibration, alpha 0.01, per-role: legit deceived 0.0082, malicious days deceived 0.063.
