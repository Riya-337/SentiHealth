# WUSTL-EHMS-2020: measured results

Public dataset (Hady et al., IEEE Access 2020): 16,318 flows, 2,046 attacks. Stratified random split 60/20/20, mean over 5 seeds.

| Setting | features | XGBoost F1 | XGBoost PR-AUC | Isolation Forest ROC-AUC | top XGBoost features (seed 0) |
|---|---|---|---|---|---|
| with identifiers | 43 | 1.000 | 1.000 | 0.700 | SrcMac, Flgs, SrcLoad |
| without identifiers | 34 | 0.709 | 0.831 | 0.700 | DIntPkt, Dur, DstJitter |

## False-alarm guarantee (threshold calibrated on benign flows, without identifiers)

| alpha | benign flows flagged (mean over seeds) | attacks flagged |
|---|---|---|
| 0.1 | 0.0996 | 0.824 |
| 0.05 | 0.0493 | 0.744 |
| 0.01 | 0.0085 | 0.620 |

Identifier columns (addresses, ports, MACs, packet number) let a model separate the attacks by memorising the capture setup; the 'without identifiers' row is the meaningful one.
