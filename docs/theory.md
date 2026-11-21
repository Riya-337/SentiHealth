# Guarantees of the deception gate

This note states and proves the guarantees behind `ml/safe_deception.py`. The setting and notation follow [`research_safe_deception.md`](research_safe_deception.md).

## Setting

A **session** $S$ is a finite sequence of events $e_1, \dots, e_{T}$ (one user or IP, no gap longer than 30 minutes). A detector, trained on data disjoint from everything below, gives each event a risk score $r_t = r(e_1, \dots, e_t)$. Any real-valued score works.

The **gate** with threshold $\tau$ deceives the session at event $t$ when the running maximum exceeds $\tau$:

$$\text{deceive at } t \iff M_t := \max_{k \le t} r_k > \tau .$$

Once deceived, a session stays deceived. Write $M(S) = M_T$ for the whole-session maximum. Because $M_1 \le M_2 \le \dots \le M_T$,

$$\{\text{the session is ever deceived}\} = \{M(S) > \tau\}. \tag{1}$$

**Calibration.** Let $S_1, \dots, S_n$ be legitimate calibration sessions with maxima $M_1, \dots, M_n$, and let $M_{(1)} \le \dots \le M_{(n)}$ be their order statistics. For a level $\alpha \in (0, 1)$ set

$$k = \lceil (n+1)(1-\alpha) \rceil, \qquad \tau = \begin{cases} M_{(k)} & k \le n,\\ +\infty & k > n.\end{cases}$$

$S_{n+1}$ denotes a new legitimate session with maximum $M_{n+1}$.

## Theorem 1 (session-level guarantee)

If $M_1, \dots, M_{n+1}$ are exchangeable, then

$$\Pr\big(S_{n+1} \text{ is ever deceived}\big) = \Pr(M_{n+1} > \tau) \le \alpha .$$

If, in addition, ties among $M_1, \dots, M_{n+1}$ have probability zero and $k \le n$, then $\Pr(M_{n+1} > \tau) \ge \alpha - \frac{1}{n+1}$.

*Proof.* The equality is (1). If $k > n$ then $\tau = +\infty$ and the probability is 0. Otherwise let $R$ be the rank of $M_{n+1}$ among $M_1, \dots, M_{n+1}$, with ties broken uniformly at random; by exchangeability $R$ is uniform on $\{1, \dots, n+1\}$. If $M_{n+1} > M_{(k)}$, at least $k$ calibration maxima are strictly smaller than $M_{n+1}$, so $R \ge k+1$. Hence

$$\Pr(M_{n+1} > \tau) \le \Pr(R \ge k+1) = \frac{n+1-k}{n+1} \le \alpha ,$$

using $k \ge (n+1)(1-\alpha)$. Without ties, $R \ge k+1$ also implies $M_{n+1} > M_{(k)}$, so equality holds in the first step, and $k < (n+1)(1-\alpha) + 1$ gives the lower bound. $\square$

**What the theorem covers.** The gate re-decides at every event, yet the bound is on *ever* being deceived during the whole session. No correction for the number of decisions is needed, because by (1) all of them reduce to one comparison of the session maximum. This is what calibrating on whole-session maxima buys.

**What it does not cover.** Calibrating on *per-event* scores at level $\alpha$ (as per-event conformal alert gating does) bounds the chance that a single event is flagged, not that a session is ever flagged. For a session of $T$ events that are roughly independent, the chance of ever crossing such a threshold is close to $1-(1-\alpha)^T$, which tends to 1 as $T$ grows. `tests/test_safe_deception.py::test_session_level_bound_covers_every_event_in_the_session` and the per-event baseline in the experiments measure this.

## Theorem 2 (per-role guarantee)

Let each session carry a group label $G$ (the user's role). Fit $\tau_g$ by the rule above on the $n_g$ calibration sessions of group $g$ only. If, for every group $g$, the maxima of the calibration sessions of group $g$ and a new legitimate session of group $g$ are exchangeable, then

$$\Pr(M_{n+1} > \tau_{G_{n+1}} \mid G_{n+1} = g) \le \alpha \quad \text{for every group } g .$$

*Proof.* Apply Theorem 1 inside group $g$. If $n_g < \lceil 1/\alpha \rceil - 1$ then $k > n_g$ and $\tau_g = +\infty$; a group never seen in calibration also gets $\tau_g = +\infty$. In both cases the probability is 0. $\square$

A single shared threshold only gives the average $\sum_g \Pr(G = g)\,\Pr(M > \tau \mid G = g) \le \alpha$, which allows one role to carry far more than $\alpha$. The experiments show this happens on real role structures (CERT r4.2).

## Proposition 3 (contaminated calibration)

In deployment, "legitimate" calibration sessions are those without a confirmed incident, so some may be attacks. Suppose the calibration set holds the $n$ clean maxima $M_1, \dots, M_n$ and $m$ further values $C_1, \dots, C_m$ that may be anything (attacks, possibly chosen by an adversary). Let $\tilde k = \lceil (n+m+1)(1-\alpha) \rceil$ and let $\tilde\tau$ be the $\tilde k$-th smallest of all $n+m$ values ($+\infty$ if $\tilde k > n+m$). If $M_1, \dots, M_{n+1}$ are exchangeable, then

$$\text{(a)}\quad \Pr(M_{n+1} > \tilde\tau) \le \alpha\Big(1 + \frac{m}{n+1}\Big),$$

$$\text{(b)}\quad \text{if every } C_i \ge \tau \text{ (the clean threshold), then } \tilde\tau \ge \tau \text{ and } \Pr(M_{n+1} > \tilde\tau) \le \alpha .$$

*Proof.* (a) If $\tilde\tau = +\infty$ there is nothing to prove. Otherwise, among the $\tilde k$ smallest values of the combined set at most $m$ are contaminants, so at least $j = \tilde k - m$ clean maxima are $\le \tilde\tau$; that is, $M_{(j)} \le \tilde\tau$. If $j \le 0$ the bound is at least 1 and holds trivially. Otherwise, as in Theorem 1,

$$\Pr(M_{n+1} > \tilde\tau) \le \Pr(M_{n+1} > M_{(j)}) \le \frac{n+1-j}{n+1} = 1 - \frac{\tilde k - m}{n+1}.$$

Since $\tilde k \ge (n+m+1)(1-\alpha)$, we get $\tilde k - m \ge (n+1)(1-\alpha) - m\alpha$, and so the right-hand side is at most $\alpha + \frac{m\alpha}{n+1}$.

(b) If every $C_i \ge \tau = M_{(k)}$, the $k-1$ smallest values of the combined set are $M_{(1)}, \dots, M_{(k-1)}$. Since $\tilde k \ge k$, the $\tilde k$-th smallest is at least $M_{(k)} = \tau$, and the claim follows from Theorem 1. $\square$

**Reading.** Contamination is *not* conservative in general: missed attacks score low, and low values can lower the threshold. But the damage is bounded. Mislabelling a fraction $m/n$ of the calibration set multiplies the guaranteed rate by at most $1 + m/(n+1)$, whatever the contaminating sessions look like, even if an adversary chooses them. With 5 % contamination and $\alpha = 1\,\%$, the bound is 1.05 %. The bound is attained: with $M_i = i$ for $i = 1, \dots, 99$, $\alpha = 0.1$ and ten contaminating values equal to 0, the threshold drops from 90 to 89 and the rate is exactly $11/100 = 0.1 \cdot (1 + 10/100)$. The same statement holds inside each group of Theorem 2, with $n, m$ replaced by the group's counts.

## Remark 4 (the rate in one deployment)

Theorems 1–3 bound the rate on average over the draw of the calibration set. For one fixed calibration set the realised rate $\rho(\tau) = \Pr(M_{n+1} > \tau \mid M_1, \dots, M_n)$ varies. If the maxima are i.i.d. with a continuous distribution, $\rho(M_{(k)})$ follows a $\mathrm{Beta}(n+1-k,\, k)$ distribution, so its spread shrinks as $n$ grows. Two consequences:

- The number of calibration sessions per role controls how close a deployment stays to $\alpha$. The experiments report per-role 95 % intervals for this reason.
- A deployment that needs $\Pr(\rho > \alpha) \le \delta$ instead of $\mathbb{E}[\rho] \le \alpha$ can use the Neyman–Pearson umbrella order: the smallest $k$ with $\Pr(\mathrm{Bin}(n, 1-\alpha) \ge k) \le \delta$ (Tong, Feng and Li, 2018). It needs more calibration sessions and deceives fewer attackers. It is implemented as `np_umbrella_threshold` and compared in the experiments.

## Remark 5 (two levels)

The gate serves noise above $\tau(\alpha_{\text{noise}})$ and full decoys above $\tau(\alpha_{\text{full}})$, with $\alpha_{\text{full}} \le \alpha_{\text{noise}}$. Each level is a gate of its own, so each bound holds separately; full decoys are a subset of deceived sessions.

## What is not guaranteed

- **Drift.** Exchangeability fails when behaviour changes after calibration (new staff, new workflows). The bound can then be exceeded; the experiments measure this and show that recalibrating on a recent window restores it. Weighted conformal prediction (Barber, Candès, Ramdas and Tibshirani, 2023) bounds the excess by the size of the shift and is the natural next step.
- **Dependence across sessions.** Sessions of the same user are not independent. Theorem 1 needs only exchangeability of the session maxima, which a random split of a fixed set provides; a time-ordered split, as in deployment, is not exchangeable in general, so it is evaluated empirically (the main protocol in every experiment).
- **Attackers who imitate legitimate staff.** The guarantee concerns legitimate sessions. It says nothing about how many attackers are deceived; an attacker who stays below $\tau$ is never deceived. The adaptive-attacker experiment measures what staying below $\tau$ costs the attacker.

## References

- V. Vovk, A. Gammerman and G. Shafer. *Algorithmic Learning in a Random World.* Springer, 2005.
- A. N. Angelopoulos and S. Bates. Conformal prediction: a gentle introduction. *Foundations and Trends in Machine Learning*, 2023.
- R. F. Barber, E. J. Candès, A. Ramdas and R. J. Tibshirani. Conformal prediction beyond exchangeability. *Annals of Statistics*, 2023.
- X. Tong, Y. Feng and J. J. Li. Neyman–Pearson classification algorithms and NP receiver operating characteristics. *Science Advances*, 2018.
