# Related work and positioning

Working draft of the paper's related-work section. Each group ends with how this work differs. Entries marked † were found through search and must be read in full, and their details checked, before they are cited.

## 1. Conformal prediction and false-alarm control

Split conformal prediction gives distribution-free, finite-sample guarantees under exchangeability (Vovk, Gammerman & Shafer, 2005; Angelopoulos & Bates, 2023). For outlier and anomaly detection, conformal p-values bound the false-positive rate of any detector, and Bates et al. (2023) give a uniform bound over thresholds. Mondrian (group-conditional) conformal prediction calibrates within each group so that the guarantee holds per group (Vovk et al., 2005). Beyond exchangeability, weighted conformal prediction bounds the excess error by the size of a distribution shift (Barber, Candès, Ramdas & Tibshirani, 2023), and adaptive conformal inference adjusts the level online under drift (Gibbs & Candès, 2021). Online conformal anomaly detection controls a sequential false discovery rate, including on a 5G intrusion testbed (†arXiv 2505.01783).

*Difference.* These methods bound the error of one decision per data point. Our gate decides at every event of a session and bounds the probability that a session is **ever** deceived, by calibrating on whole-session maxima (Theorem 1). We also bound the effect of mislabelled calibration data for any contamination, including adversarial (Proposition 3). Per-event calibration, the natural reading of conformal false-alarm control in a stream, does not give the session-level bound; we show this empirically.

## 2. Conformal methods in security

Transcend uses conformal evaluation to detect concept drift in malware classifiers and to reject unreliable predictions (Jordaney et al., USENIX Security 2017); Transcending Transcend formalises and extends it (Barbero, Pendlebury, Pierazzi & Cavallaro, IEEE S&P 2022). Two recent preprints apply conformal calibration to automated security actions. ConformalGuard (†arXiv 2610.14365) calibrates classifier scores on confirmed-legitimate events and maps p-values to tiers of intervention, from auto-clear to blocking, with a bound on the legitimate-event rate per tier. A dual-threshold conformal deferral design for SOC alert triage (†preprints.org, not peer reviewed) auto-escalates high-score alerts with finite-sample marginal guarantees.

*Difference.* ConformalGuard is the closest work. Both use conformal calibration on legitimate data to gate an automated action. We differ in four ways: (i) the guarantee is per **session** over repeated decisions, not per event; (ii) it holds **per role** (Mondrian), so false actions cannot concentrate on one staff group, which a pooled guarantee allows and which we observe on CERT r4.2; (iii) the action is **deception**, whose harm model (a clinician served fake records) differs from blocking; (iv) we give a contamination bound and measure behaviour under drift, time-ordered calibration and an adaptive attacker. Transcend uses conformal scores to judge model reliability, not to control the harm of a defensive action.

## 3. Deception for defence

Honeytokens and decoy documents detect intruders because legitimate users should never touch them (Spitzner, 2003; Bowen, Hershkop, Keromytis & Stolfo, SecureComm 2009); honeywords apply the same idea to password files (Juels & Rivest, CCS 2013). In healthcare, decoys must be adapted to structured EHR data rather than documents. Game-theoretic work models when, where and how to deceive (Pawlick, Colbert & Zhu, ACM Computing Surveys 2019; Stackelberg timing of deception, †arXiv 2505.21244), treating deception as a resource and modelling the attacker's beliefs.

*Difference.* Static decoys assume legitimate users never encounter them, so their false-positive rate is near zero by construction. We study **served** deception, where the defender decides at run time to show decoy data to a suspected session. Here legitimate users can be deceived, and in a hospital that harm matters. To our knowledge, no prior deception work bounds how often legitimate users are deceived; the game-theoretic models optimise the defender's payoff against attackers and do not model the cost to benign users.

## 4. Group-conditional guarantees and fairness

Fairness criteria such as equalised odds constrain error rates across groups (Hardt, Price & Srebro, NeurIPS 2016). Equalised coverage applies the same idea to conformal prediction by calibrating within groups (Romano, Barber, Sabatti & Candès, *Harvard Data Science Review* 2020). Neyman–Pearson classification bounds one error type with high probability over the training draw (Tong, Feng & Li, *Science Advances* 2018).

*Difference.* We use group-conditional calibration as a **safety** requirement: no role may carry more than α of the false deceptions. We show that a shared threshold violates it badly on CERT r4.2 (up to 22 % for one role at α = 1 % with an unsupervised detector, time-ordered calibration), compare against a per-role Neyman–Pearson rule, and measure two prices of per-role thresholds: an attacker who controls an account of the most permissive role gets the most room (role shopping), and in roles with few members one person's behaviour change can push the whole role above α.

## 5. Insider threat and EHR misuse detection

CERT r4.2 is the standard synthetic insider-threat benchmark (Glasser & Lindauer, IEEE S&P Workshops 2013). Detection of inappropriate EHR access has used explanation-based auditing and anomaly detection on access logs (CADS and successors; see the research note). WUSTL-EHMS-2020 provides network and medical-sensor data with attacks for healthcare intrusion detection (Hady et al., *IEEE Access* 2020).

*Difference.* We do not propose a new detector. The gate works with any score, and we evaluate it with a supervised and an unsupervised detector. On WUSTL-EHMS-2020 we also show that identifier columns let a model separate attacks by memorising the capture setup (F1 1.00 → 0.71 without them), a pitfall for results reported on this dataset.

## Claims to keep (and their evidence)

1. A session-level, anytime guarantee on deceiving legitimate users, for any detector (Theorem 1; simulator and CERT session experiments).
2. Per-role guarantees, evidence that shared thresholds concentrate harm on some roles, and a characterisation of when per-role thresholds fail: individual behaviour change in small roles with a supervised detector (Theorem 2; CERT r4.2 sessions and user-days).
3. A bound on the effect of mislabelled calibration data, tight in the worst case, replacing the common assumption that contamination is harmless (Proposition 3; stealthy-contamination experiments).
4. An empirical safety–deception frontier with time-ordered calibration, baselines, drift and an adaptive attacker.

## References

- A. N. Angelopoulos and S. Bates. Conformal prediction: a gentle introduction. *Foundations and Trends in Machine Learning*, 2023.
- R. F. Barber, E. J. Candès, A. Ramdas and R. J. Tibshirani. Conformal prediction beyond exchangeability. *Annals of Statistics*, 2023.
- F. Barbero, F. Pendlebury, F. Pierazzi and L. Cavallaro. Transcending Transcend: revisiting malware classification in the presence of concept drift. *IEEE S&P*, 2022.
- S. Bates, E. Candès, L. Lei, Y. Romano and M. Sesia. Testing for outliers with conformal p-values. *Annals of Statistics*, 2023.
- B. M. Bowen, S. Hershkop, A. D. Keromytis and S. J. Stolfo. Baiting inside attackers using decoy documents. *SecureComm*, 2009.
- I. Gibbs and E. Candès. Adaptive conformal inference under distribution shift. *NeurIPS*, 2021.
- J. Glasser and B. Lindauer. Bridging the gap: a pragmatic approach to generating insider threat data. *IEEE Security and Privacy Workshops*, 2013.
- A. A. Hady et al. Intrusion detection system for healthcare systems using medical and network data: a comparison study. *IEEE Access*, 2020.
- M. Hardt, E. Price and N. Srebro. Equality of opportunity in supervised learning. *NeurIPS*, 2016.
- R. Jordaney et al. Transcend: detecting concept drift in malware classification models. *USENIX Security*, 2017.
- A. Juels and R. L. Rivest. Honeywords: making password-cracking detectable. *ACM CCS*, 2013.
- J. Pawlick, E. Colbert and Q. Zhu. A game-theoretic taxonomy and survey of defensive deception for cybersecurity and privacy. *ACM Computing Surveys*, 2019.
- Y. Romano, R. F. Barber, C. Sabatti and E. Candès. With malice toward none: assessing uncertainty via equalized coverage. *Harvard Data Science Review*, 2020.
- L. Spitzner. Honeytokens: the other honeypot. *SecurityFocus*, 2003.
- X. Tong, Y. Feng and J. J. Li. Neyman–Pearson classification algorithms and NP receiver operating characteristics. *Science Advances*, 2018.
- V. Vovk, A. Gammerman and G. Shafer. *Algorithmic Learning in a Random World.* Springer, 2005.
- † ConformalGuard: false-positive-controlled action gating for LM classifiers. arXiv 2610.14365.
- † Dual-threshold conformal deferral for SOC alert triage. Preprint, preprints.org (not peer reviewed).
- † Online conformal anomaly detection with prediction-powered data acquisition. arXiv 2505.01783.
- † When to deceive: a cross-layer Stackelberg game framework for strategic timing of cyber deception. arXiv 2505.21244.
