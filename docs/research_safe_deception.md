# Safety-bounded deception for clinical information systems

*Working note for a paper. Status: method implemented, evaluated on a simulator and two public datasets. Novelty still has to be confirmed by a full literature search before submission.*

## 1. Problem

Deception (honey records, decoy data, noise) is attractive in hospitals: an attacker who exfiltrates decoys gains nothing, and canary tokens inside the decoys trace any later leak. But a hospital cannot accept the obvious failure mode: **a clinician who is mistaken for an attacker and served fake patient data** can harm a patient. Existing deployments either avoid deception in clinical systems or switch it on above a fixed risk threshold. A fixed threshold gives no statement about how often legitimate staff are deceived, and that rate silently changes with the detector, with the role (night nurses look different from billing staff) and over time.

**Question.** Can a hospital choose an acceptable risk level α (say 1 legitimate session in 1,000) and have a deception policy that provably respects it, whatever detector it uses, while still deceiving as many attackers as possible?

## 2. Method

Let a *session* be one user/IP's activity with no gap longer than 30 minutes, and let r_t be the detector's risk score at event t of the session. Any score works: probabilities, anomaly scores, rules turned into numbers.

1. **Sequential decision.** At event t, deceive iff the running maximum M_t = max_{k≤t} r_k exceeds τ; once deceived, the session stays deceived.
2. **Session-level calibration.** Take n sessions known to be legitimate and their whole-session maxima M_T(s_1..s_n). Set τ to the ⌈(n+1)(1−α)⌉-th smallest of them (split conformal prediction).
3. **Per-role thresholds (Mondrian).** Fit τ_g separately for each role g on that role's sessions only. Groups that cannot contain clinicians (unauthenticated traffic) use the pooled τ; an unknown staff role gets τ = ∞ (never deceived).
4. **Graded response.** Noise-only above τ(α₁), full decoys above τ(α₂) with α₂ ≤ α₁.

**Guarantee.** If the calibration sessions and a new legitimate session are exchangeable (within its role, for the Mondrian version), then

  P(new legitimate session is *ever* deceived) = P(M_T > τ) ≤ α,

because M_t ≤ M_T for all t and the split-conformal argument bounds P(M_T > τ). The bound is *anytime* over the session: the repeated per-event decisions do not add up. Calibrating on per-event scores instead would not give this; in our test (`tests/test_safe_deception.py`) per-event calibration deceives most legitimate 40-event sessions at least once at α = 0.05.

**Contamination is conservative.** Undetected attacks in the "legitimate" calibration set have larger maxima and can only raise τ: the safety bound still holds, at a cost in detection.

**What is not guaranteed.** Exchangeability fails under drift (new workflows, new staff) and across calendar effects. The system therefore recalibrates on a recent window and monitors the realised rate on verified-legitimate sessions with a one-sided binomial test (`monitor()`).

## 3. Experiments

Code: `ml/safe_deception.py`, `ml/experiments/deception_guarantee.py`, `ml/datasets/wustl_ehms.py`, `ml/datasets/cert_r42.py`. Results: `evaluation/DECEPTION.md`, `evaluation/WUSTL_EHMS.md`, `evaluation/CERT_R42.md`.

### 3.1 Simulator (5 seeds, 300 users, 28 days, about 1.7 M minute-records per seed)

Detectors trained on the first half; post-training sessions split at random into calibration and test.

| α | legit sessions ever deceived, per-role gate (mean) | worst role, **pooled** gate | worst role, **per-role** gate | attack sessions deceived (XGBoost) | attacker EHR reads that hit decoys |
|---|---|---|---|---|---|
| 0.10 | 0.099 | 0.126 | 0.101 | 0.976 | 0.986 |
| 0.05 | 0.048 | 0.075 | 0.050 | 0.969 | 0.967 |
| 0.02 | 0.018 | 0.040 | 0.023 | 0.959 | 0.649 |
| 0.01 | 0.007 | 0.017 | 0.015 | 0.927 | 0.396 |

Findings:
- **The bound holds** (realised rate ≈ α or below, overall and per role).
- **Pooled calibration hides concentrated harm**: at α = 0.05 the worst role is deceived at 7.5 % under a pooled threshold, 5.0 % with per-role thresholds.
- **Safety and deception trade off explicitly**: at α = 0.05 the supervised detector still puts 97 % of attack sessions on deception and 97 % of attacker record reads hit decoys; at α = 0.01, attackers are still deceived (93 %) but later, so only 40 % of their reads are decoys. Full decoys need about 1/α₂ calibration sessions per role.
- **Contamination** (α = 0.01): adding 1 % / 5 % attack sessions to calibration lowers false deceptions to 0.09 % / 0 %, and attacker coverage to 86 % / 18 %. Safe but costly.
- **Drift** (legitimate read rates × 1.8): the stale gate deceives 2.9 % of legitimate sessions at α = 0.01; recalibrating on 7 days after the change restores 1.05 %.
- **Time-ordered calibration** (no random split): 1.19 % at α = 0.01; calendar differences between the halves cost a little.

### 3.2 WUSTL-EHMS-2020 (public healthcare testbed)
- Identifier leakage: F1 = 1.000 with addresses/MACs (the top feature is the source MAC) versus 0.709 without them.
- The same conformal construction bounds the false-alarm rate on benign flows: 9.96 % at α = 0.10, 4.93 % at 0.05, 0.85 % at 0.01.

### 3.3 CERT Insider Threat r4.2 (public benchmark)

330,285 user-days (1,000 users, 541 malicious days, 35 role groups from the LDAP snapshots). Detectors trained on the first half of the period; later days split at random into calibration and evaluation; 5 seeds. XGBoost ROC-AUC 0.998 / PR-AUC 0.893; Isolation Forest 0.890 / 0.019.

| α | detector | legit days deceived, pooled | **worst role, pooled** | legit days deceived, per-role | worst role, per-role | malicious days deceived (per-role) |
|---|---|---|---|---|---|---|
| 0.10 | XGBoost | 0.101 | **0.376** | 0.100 | 0.114 | 0.997 |
| 0.05 | XGBoost | 0.050 | **0.196** | 0.050 | 0.064 | 0.991 |
| 0.01 | XGBoost | 0.010 | **0.044** | 0.010 | 0.013 | 0.957 |
| 0.10 | Isolation Forest | 0.101 | **0.997** | 0.102 | 0.120 | 0.680 |
| 0.05 | Isolation Forest | 0.051 | **0.914** | 0.051 | 0.062 | 0.517 |
| 0.01 | Isolation Forest | 0.010 | **0.219** | 0.010 | 0.014 | 0.148 |

Findings:
- **A pooled threshold meets α on average while one role absorbs the harm**: with the unsupervised detector at α = 0.10, one role is deceived on 99.7 % of its normal days; even the supervised detector hits one role at 3.8 × α. Per-role thresholds keep every role close to α (the small excess of the *worst* role is the maximum over 35 noisy group estimates).
- With the supervised detector, the per-role gate at α = 0.01 still deceives 95.7 % of malicious days.
- Time-ordered calibration at α = 0.01: 1.02 % (XGBoost) and 0.83 % (Isolation Forest) of normal days deceived.

## 4. Claimed contributions (to be checked against the literature)

1. Formulating clinical deception as a *safety-constrained* decision with a user-chosen bound on deceiving legitimate staff.
2. A session-level, anytime conformal gate (running maximum, calibrated on session maxima) that works with any detector, plus per-role (Mondrian) thresholds and a fail-safe for unseen roles.
3. An empirical safety–deception frontier, with contamination and drift analyses, on a simulator and public datasets.

## 5. Related work to cite and position against
- Conformal prediction: Vovk, Gammerman & Shafer (2005); Angelopoulos & Bates (2023 tutorial); Mondrian conformal; adaptive conformal inference under drift (Gibbs & Candès 2021).
- Conformal methods already used for intrusion/anomaly detection (false-alarm control): we must show the difference is the session-level deception decision and the safety framing.
- Deception in healthcare: DICOMHawk; RAID 2025 healthcare web deception networks; LLM-generated honey records (NPS).
- EHR access-log misuse detection: CADS; Hurst et al. 2022; BMC Med. Inform. 2024 (Isolation Forest + SVM).

## 6. Limitations
- The simulator and the detector were written by the same author; the public datasets are a network testbed (WUSTL) and a synthetic enterprise (CERT), not real hospital EHR logs.
- The guarantee depends on exchangeability; drift needs recalibration and monitoring.
- "Legitimate" calibration labels in deployment come from the absence of confirmed incidents and analyst labels; this is conservative (see contamination) but must be stated.
