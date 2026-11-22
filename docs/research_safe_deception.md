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

**Contamination is conservative only for high-scoring attacks.** Let τ be the threshold from the clean calibration set. Adding sessions whose maxima are all ≥ τ cannot lower the threshold: the clean set's k−1 smallest maxima stay the k−1 smallest, so the new k′-th smallest (k′ ≥ k) is ≥ τ. Adding sessions that score *below* τ can lower it. Example: 99 calibration sessions with maxima 1…99 and α = 0.1 give τ = 90; adding ten sessions with maximum 0 gives τ = 89. The attacks most likely to be mislabelled as legitimate are the ones the detector missed, which score low, so contamination is **not** conservative in general. Section 3 measures both cases: random attack sessions (mostly high-scoring) and the stealthiest (lowest-scoring) ones.

**What is not guaranteed.** Exchangeability fails under drift (new workflows, new staff) and across calendar effects. The system therefore recalibrates on a recent window and monitors the realised rate on verified-legitimate sessions with a one-sided binomial test (`monitor()`).

## 3. Experiments

Code: `ml/safe_deception.py`, `ml/experiments/deception_guarantee.py`, `ml/experiments/adaptive_attacker.py`, `ml/datasets/wustl_ehms.py`, `ml/datasets/cert_r42.py`, `ml/datasets/cert_sessions.py`. Results: `evaluation/DECEPTION.md`, `evaluation/ADAPTIVE.md`, `evaluation/WUSTL_EHMS.md`, `evaluation/CERT_R42.md`, `evaluation/CERT_SESSIONS.md`. Theory: [`theory.md`](theory.md). Related work: [`related_work.md`](related_work.md).

**Protocol in every experiment.** Detectors are trained on the first half of the period. The main protocol is **time-ordered**: earlier post-training sessions calibrate the gate, later ones evaluate it, as a deployment would. A random split of the same sessions (the exchangeable setting of the theorems) is reported as a secondary check. Rates are pooled over 5 seeds with 95 % Clopper–Pearson intervals; "roles above α" counts roles whose rate is significantly above α (one-sided binomial test, Holm-corrected across roles, 5 %).

### 3.1 Simulator (5 seeds, 300 users, 28 days, about 1.7 M minute-records per seed)

Supervised detector (XGBoost), five staff roles plus unauthenticated traffic:

| α | per-role gate, time-ordered [95 % CI] | roles above α | per-role gate, random split | shared threshold, worst role (time-ordered) | attack sessions deceived | attacker reads on decoys |
|---|---|---|---|---|---|---|
| 0.10 | 9.66 % [9.00, 10.35] | 0 / 25 | 9.87 % | 12.37 % | 97.2 % | 98.4 % |
| 0.05 | 5.04 % [4.55, 5.56] | 0 / 25 | 4.80 % | 7.48 % | 96.1 % | 95.9 % |
| 0.02 | 2.25 % [1.93, 2.61] | 1 / 25 | 1.77 % | 4.66 % | 95.4 % | 74.5 % |
| 0.01 | 1.19 % [0.95, 1.46] | 2 / 25 | 0.67 % | 2.54 % | 94.3 % | 51.6 % |

Findings:
- **Calibrating on whole sessions is essential.** Calibrating on per-event scores (as per-event conformal gating does) deceives 61 % of legitimate sessions at α = 1 % and 93 % at α = 5 %, because a session makes many decisions. Calibrating on session maxima gives 1.2 % and 5.0 % (Theorem 1).
- **The bound holds under the random split** (0.67 % at α = 1 %). **Time-ordered calibration exceeds it slightly** (1.19 % at α = 1 %, 2.25 % at α = 2 %, the latter significantly above α): calendar differences between the calibration and evaluation periods break exchangeability a little. This is the realistic number and the paper should lead with it.
- **Shared thresholds put more harm on some roles**: 4–5 of 25 role-seeds are significantly above α under a shared threshold at α = 5–10 %, none under the per-role gate. With only five staff roles the gap is smaller than on CERT.
- **Baselines.** The per-role Neyman–Pearson rule keeps every role below α with high probability but deceives far fewer attackers at small α (65 % vs 94 % of attack sessions at α = 1 %). Per-role quantiles without the finite-sample correction overshoot (1.65 % at α = 1 %, 5 roles above α at α = 0.5 %).
- **Contamination** (α = 1 %, shared threshold): random mislabelled attacks make the gate more conservative (0.08 % at 1 %, 0 % at 5 % contamination) at a large cost in detection. The stealthiest attacks barely move the rate (Isolation Forest: 1.04 % → 1.08 % at 5 % contamination), within the 1 + m/(n+1) factor of Proposition 3.
- **Drift** (legitimate read rates × 1.8): the stale gate deceives 2.9 % of legitimate sessions at α = 1 %; recalibrating on the 7 days after the change restores 1.05 %.
- **Trade-off**: at α = 5 %, 96 % of attack sessions are deceived and 96 % of attacker record reads hit decoys; at α = 1 %, attackers are still deceived (94 %) but later, so 52 % of their reads are decoys.

### 3.1b Adaptive attacker (simulator, `evaluation/ADAPTIVE.md`)

An attacker who knows the gate and its thresholds scales its activity towards a legitimate role's average profile (feature-space mimicry; time of day, IP reputation and address kept as they were) until no event is deceived. λ* is the share of its activity rate it can keep. XGBoost, α = 1 %, 996 attack sessions over 5 seeds, median λ*:

| family | shared threshold | per-role gate | per-role, role shopping |
|---|---|---|---|
| brute force, DDoS | 0.00 | 0.00 | 0.00 |
| exfiltration | 0.05 | 0.05 | 0.20 |
| ransomware | 0.10 | 0.15 | 0.15 |
| off-hours insider | 0.30 | 0.25 | **0.95** |
| credential stuffing | 0.85 | 0.85 | 0.90 |
| slow exfiltration | 0.90 | 0.90 | 0.90 |

Findings:
- Loud attacks cannot avoid deception without becoming normal behaviour; fast exfiltration and ransomware keep 5–15 % of their speed.
- Attacks that are already slow (credential stuffing, slow exfiltration) evade at little cost. This is a limit of rate-based detectors, not of the gate, and the paper must state it.
- **Role shopping is the price of per-role thresholds.** An insider who controls an account of the most permissive role (IT staff, billing or doctor, depending on the seed) keeps 95 % of its off-hours activity instead of 25 %. Mitigations to evaluate: a floor that caps each role's threshold at the shared one, or deceiving on the account's expected role rather than its claimed one.
- Feature interpolation gives the attacker more freedom than real behaviour would, so these costs are lower bounds.

### 3.2 WUSTL-EHMS-2020 (public healthcare testbed)
- Identifier leakage: F1 = 1.000 with addresses/MACs (the top feature is the source MAC) versus 0.709 without them.
- The same conformal construction bounds the false-alarm rate on benign flows: 9.96 % at α = 0.10, 4.93 % at 0.05, 0.85 % at 0.01.

### 3.3 CERT Insider Threat r4.2 (public benchmark)

Two experiments. **User-days** (`evaluation/CERT_R42.md`): 330,285 user-days, 1,000 users, 541 malicious days, one decision per day. **Sessions** (`evaluation/CERT_SESSIONS.md`): 4.13 M logon, USB, file and e-mail events grouped into 1.44 M sessions (1,540 containing malicious events), the gate re-deciding at every event. Both use 5 seeds, 39 role groups, and time-ordered calibration as the main protocol.

**Sessions, α = 1 %**, time-ordered unless stated. *Roles above α*: role-seeds significantly above α (Holm, 5 %), first treating sessions as independent and then with users as clusters (user-level bootstrap, roles with at least 5 users; 145 role-seeds). Sessions of one person are dependent, so the user-level count is the valid one.

| detector | rule | overall | worst role | roles above α: sessions independent | **users as clusters** | shared threshold, users as clusters | malicious sessions deceived |
|---|---|---|---|---|---|---|---|
| Isolation Forest | per-role gate | 0.96 % | 1.48 % | 0 / 195 | **0 / 145** | 5 / 145 | 3.4 % |
| Isolation Forest | per-role gate, random split | 0.99 % | 1.17 % | 2 / 195 | 0 / 150 | 8 / 150 | 3.6 % |
| XGBoost | per-role gate | 1.01 % | 6.68 % | 61 / 195 | **0 / 145** | 5 / 145 | 66.3 % |
| XGBoost | per-role gate, random split | 1.01 % | 1.22 % | 4 / 195 | 0 / 150 | 6 / 150 | 57.6 % |
| XGBoost | per-event conformal | 1.39 % | 16.11 % | 63 / 195 | 10 / 145 | — | 75.2 % |

User-days, α = 1 %, time-ordered: per-role gate 0 / 145 (both detectors); shared threshold 1 / 145 (XGBoost) and 5 / 145 (Isolation Forest, worst role 21.8 %).

Findings:
- **The overall rate matches α everywhere**, for both detectors, both protocols, user-days and sessions.
- **A shared threshold concentrates harm on some roles**: with Isolation Forest, one role is deceived on 13–22 % of its normal sessions or days at α = 1 % (and on 99.5 % of days at α = 10 %). The per-role gate keeps every role near α.
- **Session-level calibration matters on real event sequences too**: per-event calibration (XGBoost, α = 1 %) gives a worst role of 16 % and 63 of 195 role-seeds above α.
- **With users as clusters, no role of five or more people is significantly above α under the per-role gate**, for either detector, in both CERT experiments; a shared threshold leaves 1–5 of 145 role-seeds above α and per-event calibration 10. Treating sessions as independent overstates failures (61 of 195 for XGBoost), because one person contributes hundreds of dependent sessions.
- **Where the per-role guarantee fails: individual behaviour change in very small roles.** With XGBoost and time-ordered calibration, roles of two or three people can show high rates, while the random split does not. The monthly rate of the static gate is stable (0.92–1.19 % at α = 1 %), and recalibrating every month on the previous 60 days does not help (worst role 7.5 %), so this is not slow drift of the whole population. Each failing role is driven by one user whose behaviour changed between the calibration period (2010) and the evaluation period (2011): in ComputerTrainer (2 users) one user goes from 5 of 355 sessions deceived to 62 of 381 and causes 94 % of the role's deceptions; NursePractitioner (3 users), ManagementTrainer (2) and PurchasingClerk (5) show the same pattern. None of these users are labelled insiders. Insiders' own unlabelled sessions add to it (deceived at 15.8 % against 0.81 % for other users) but do not explain it: excluding insiders, 10 of 39 roles still exceed α on a session-level test (seed 0).
- **Consequences.** (i) Exchangeability is violated at the level of individual people: a role with two or three members inherits each member's behaviour change. Requiring at least 10 users per role group (smaller roles pooled) lowers the worst role from 7.0 % to 2.3 % (one seed) but does not restore α. (ii) Sessions of the same user are not independent: session-level binomial tests are badly optimistic, and every claim above uses user-level (cluster bootstrap) tests, restricted to roles with at least 5 users because a bootstrap over two or three people is unreliable. (iii) The supervised detector's scores separate users more sharply than the anomaly detector's, which makes them more sensitive to one user's change. A per-user cap on deceptions, or hierarchical role/user calibration, is the natural next step.
- **Detection.** XGBoost deceives 66 % of malicious sessions at α = 1 % (session ROC-AUC 0.92); Isolation Forest, whose per-role guarantee holds, deceives only 3–4 %. The detector that is safe here is weak, and the strong one is not reliably safe per role: the paper must report this trade-off.
- **Contamination** at α = 1 % (up to 5 % mislabelled malicious sessions, random or stealthiest) changes the rate by at most 0.09 percentage points in either direction, inside Proposition 3.

## 4. Claimed contributions (to be checked against the literature)

1. Formulating clinical deception as a *safety-constrained* decision with a user-chosen bound on deceiving legitimate staff.
2. A session-level, anytime conformal gate (running maximum, calibrated on session maxima) that works with any detector, plus per-role (Mondrian) thresholds and a fail-safe for unseen roles (Theorems 1–2).
3. A bound on the effect of mislabelled calibration data, tight in the worst case (Proposition 3).
4. An empirical study on a simulator and two public datasets with time-ordered calibration, baselines, contamination, drift and an adaptive attacker, including where the per-role guarantee fails (individual behaviour change in small roles, role shopping).

## 5. Related work to cite and position against
- Conformal prediction: Vovk, Gammerman & Shafer (2005); Angelopoulos & Bates (2023 tutorial); Mondrian conformal; adaptive conformal inference under drift (Gibbs & Candès 2021).
- Conformal methods already used for intrusion/anomaly detection (false-alarm control): we must show the difference is the session-level deception decision and the safety framing.
- Deception in healthcare: DICOMHawk; RAID 2025 healthcare web deception networks; LLM-generated honey records (NPS).
- EHR access-log misuse detection: CADS; Hurst et al. 2022; BMC Med. Inform. 2024 (Isolation Forest + SVM).

## 6. Limitations
- The simulator and the detector were written by the same author; the public datasets are a network testbed (WUSTL) and a synthetic enterprise (CERT), not real hospital EHR logs.
- The guarantee depends on exchangeability. Population drift is handled by recalibration; behaviour change of individual users in small roles is not (CERT, section 3.3).
- Per-role thresholds give an attacker who controls an account of the most permissive role more room (section 3.1b).
- On CERT the detector whose per-role guarantee holds (Isolation Forest) catches few insiders; the strong supervised detector does not keep every role below α.
- "Legitimate" calibration labels in deployment come from the absence of confirmed incidents and analyst labels. Missed (low-scoring) attacks in that set can lower τ, so the bound then holds only approximately; see the contamination results.
