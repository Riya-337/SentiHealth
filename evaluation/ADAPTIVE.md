# Adaptive attacker: the cost of avoiding the deception gate

Generated 2026-11-21T16:06:30+00:00. **Synthetic data**, 5 seeds, 28 days, 300 users per seed, 996 attack sessions in the evaluation period. The attacker knows the gate and its thresholds and scales its activity towards a legitimate role's average profile until no event is deceived. lambda* = share of its activity rate it can keep (1 = the original attack, 0 = average legitimate behaviour). See the docstring of ml/experiments/adaptive_attacker.py for the model and its limits.

## Detector: xgb

| alpha | gate | median lambda* | mean lambda* | sessions never deceived as they were (lambda* = 1) | sessions keeping >= 50 % |
|---|---|---|---|---|---|
| 0.05 | shared threshold | 0.55 | 0.45 | 4.1 % | 52.7 % |
| 0.05 | per-role, own role | 0.50 | 0.45 | 4.0 % | 51.6 % |
| 0.05 | per-role, role shopping | 0.47 | 0.43 | 4.5 % | 50.0 % |
| 0.01 | shared threshold | 0.70 | 0.53 | 6.4 % | 57.9 % |
| 0.01 | per-role, own role | 0.70 | 0.54 | 5.7 % | 58.0 % |
| 0.01 | per-role, role shopping | 0.75 | 0.58 | 11.5 % | 62.2 % |

Per attack family, alpha = 0.01, median lambda* (shared / per-role / role shopping):

| family | sessions | shared | per-role | role shopping |
|---|---|---|---|---|
| brute_force | 55 | 0.00 | 0.00 | 0.00 |
| brute_force_slow | 19 | 0.00 | 0.00 | 0.00 |
| credential_stuffing | 397 | 0.85 | 0.85 | 0.90 |
| ddos_mild | 159 | 0.00 | 0.00 | 0.00 |
| ddos_severe | 74 | 0.00 | 0.00 | 0.00 |
| exfiltration | 29 | 0.05 | 0.05 | 0.20 |
| exfiltration_slow | 188 | 0.90 | 0.90 | 0.90 |
| insider_offhours | 22 | 0.30 | 0.25 | 0.95 |
| ransomware | 13 | 0.10 | 0.15 | 0.15 |
| recon | 40 | 1.00 | 1.00 | 1.00 |

Role an attacker would shop for at alpha = 0.01: billing, doctor, it_staff (per seed: it_staff, billing, it_staff, it_staff, doctor).

## Detector: iforest

| alpha | gate | median lambda* | mean lambda* | sessions never deceived as they were (lambda* = 1) | sessions keeping >= 50 % |
|---|---|---|---|---|---|
| 0.05 | shared threshold | 0.35 | 0.44 | 19.3 % | 35.6 % |
| 0.05 | per-role, own role | 0.35 | 0.44 | 19.3 % | 36.4 % |
| 0.05 | per-role, role shopping | 0.40 | 0.49 | 20.4 % | 43.8 % |
| 0.01 | shared threshold | 1.00 | 0.84 | 54.8 % | 87.6 % |
| 0.01 | per-role, own role | 1.00 | 0.83 | 55.7 % | 85.4 % |
| 0.01 | per-role, role shopping | 1.00 | 0.88 | 66.9 % | 90.8 % |

Per attack family, alpha = 0.01, median lambda* (shared / per-role / role shopping):

| family | sessions | shared | per-role | role shopping |
|---|---|---|---|---|
| brute_force | 55 | 0.30 | 0.30 | 0.30 |
| brute_force_slow | 19 | 0.65 | 0.65 | 0.65 |
| credential_stuffing | 397 | 0.85 | 0.85 | 0.95 |
| ddos_mild | 159 | 1.00 | 1.00 | 1.00 |
| ddos_severe | 74 | 1.00 | 1.00 | 1.00 |
| exfiltration | 29 | 0.20 | 0.20 | 0.25 |
| exfiltration_slow | 188 | 1.00 | 1.00 | 1.00 |
| insider_offhours | 22 | 1.00 | 1.00 | 1.00 |
| ransomware | 13 | 0.50 | 0.50 | 0.65 |
| recon | 40 | 1.00 | 1.00 | 1.00 |

Role an attacker would shop for at alpha = 0.01: admin, doctor, it_staff (per seed: it_staff, it_staff, admin, doctor, doctor).

## Reading the tables

- A low lambda* means the attacker must slow down to close to normal behaviour to stay undeceived: deception then costs it most of its speed.
- Role shopping shows the price of per-role thresholds: an attacker who controls an account of the most permissive role gets the most room.
- Interpolated feature vectors are not all reachable by real behaviour, so these costs are lower bounds on what a real attacker pays.
