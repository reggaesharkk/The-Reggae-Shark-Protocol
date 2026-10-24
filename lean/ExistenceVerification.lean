import Mathlib.Analysis.SpecialFunctions.Trigonometric.Basic
import Mathlib.Analysis.SpecialFunctions.Trigonometric.Deriv
import Mathlib.Topology.MetricSpace.Basic
import Mathlib.Tactic

/-!
# Pointwise Boundary-Face & Linear-Comparison Algebra for the 4D Soft-Wall ODE System (`B_4`)
## Appendix B v1.0 — Bounded Self-Referential Dynamics & Ψ-Memory Persistence

This Lean 4 module (`ExistenceVerification.lean`, registered as a default library target in
`lakefile.lean` alongside `BoundaryVerification.lean` under `leanprover/lean4:v4.36.0-rc1`
and Mathlib commit `10156080d0e7`) formalizes the algebraic vector field
`F_exist = (dgamma_dt_4D, dHobs_dt_4D, dIdot_dt_4D, dPsi_dt_4D)` on the dimensionless 4D state
`ExistenceState = (γ, H_obs, İ, Ψ)` with the smooth quadratic self-feedback ratio:
`R_self_sq(s) = fb(s)^2 / (fb(s)^2 + (f * P_0)^2 + sigma_0^2)`.

Scope of this module (17 machine-checked pointwise algebraic theorems, **zero `sorry` axioms,
zero `nlinarith` tactics**):
1. **Unconditional Non-Negativity of State-Dependent `R_self_sq`** (`R_self_sq_nonneg`):
   Proves `0 ≤ R_self_sq ... s` from `sq_nonneg`, `add_nonneg`, and `div_nonneg`.
2. **Derived Upper & Lower Entropy-Rate Bounds on `B_4`** (`dHobs_dt_4D_le_M_H` and
   `dHobs_dt_4D_ge_neg_M_H`): Proves `-M_H_4D ≤ dHobs_dt_4D ≤ M_H_4D` directly from box
   membership (`0 ≤ s.gamma ≤ gamma_max`, `0 ≤ s.H_obs ≤ H_max`).
3. **All Eight Pointwise Boundary-Face Sign Conditions on `B_4`** (Faces 1–8, including both
   `P_0 > 0` in `dIdot_dt_4D_pos_at_boundary` and `P_0 ≥ 0` in
   `dIdot_dt_4D_nonneg_at_boundary_zero_drive`).
4. **Pointwise Linear Comparison Lower Bounds for `γ` and `İ`** (`dgamma_dt_4D_ge_neg_decay`
   proving `-(b * γ) ≤ dγ/dt`, and `dIdot_dt_4D_ge_linear_floor` proving
   `f P_0 - e ((İ / ε_I) M_H_4D) - g İ ≤ dİ/dt` on `B_4`). Continuous-time forward invariance
   and Grönwall / uniform `liminf` persistence follow from these pointwise inequalities via
   classical ODE comparison theorems in the accompanying manuscript.
5. **Unified 8-Face 4D Box Pointwise Certificate** (`existence_box_8face_nagumo_certificate`).
-/

noncomputable section

/-- Dimensionless 4D state-space coordinates `(γ, H_obs, İ, Ψ)` of the soft-wall ODE system. -/
structure ExistenceState where
  gamma : ℝ  -- Dimensionless reconstruction capacity (γ ∈ [0, γ_max])
  H_obs : ℝ  -- Dimensionless internal entropy / uncertainty coordinate (H_obs ∈ [0, H_max])
  I_dot : ℝ  -- Dimensionless processing rate coordinate (İ ∈ [0, İ_max_4D])
  Psi   : ℝ  -- Dimensionless slow-memory / self-feedback coordinate (Ψ ∈ [0, 1])

/-- Effective input drive:
`P_eff(γ, Ψ) = P_0 + λ_sim * r_lrsc * γ + λ_lucid * Ψ`.
Note that `λ_sim` and `r_lrsc` enter solely through their product `Λ_eff = λ_sim * r_lrsc`. -/
def P_eff (P_0 lam_sim r_lrsc lam_lucid : ℝ) (s : ExistenceState) : ℝ :=
  P_0 + lam_sim * r_lrsc * s.gamma + lam_lucid * s.Psi

/-- Upper bound `P_eff_max = P_0 + λ_sim * r_lrsc * γ_max + λ_lucid` on `[0, γ_max] × [0, 1]`. -/
def P_eff_max (P_0 lam_sim r_lrsc gamma_max lam_lucid : ℝ) : ℝ :=
  P_0 + lam_sim * r_lrsc * gamma_max + lam_lucid

/-- Eq. (B.1): Reconstruction capacity dynamics `dγ/dt = a İ E_avail (1 - γ / γ_max) - b γ`. -/
def dgamma_dt_4D (a b E_avail gamma_max : ℝ) (s : ExistenceState) : ℝ :=
  a * s.I_dot * E_avail * (1 - s.gamma / gamma_max) - b * s.gamma

/-- Eq. (B.2): Soft-wall entropy dynamics `dH_obs/dt = c γ (H_max - H_obs) - İ_erase tanh(H_obs / ε_H)`. -/
def dHobs_dt_4D (c H_max I_erase epsH : ℝ) (s : ExistenceState) : ℝ :=
  c * s.gamma * (H_max - s.H_obs) - I_erase * Real.tanh (s.H_obs / epsH)

/-- Eq. (B.3): Coupled processing dynamics
`dİ/dt = e tanh(İ / ε_I) (dH_obs/dt) + f P_eff(γ, Ψ) - g İ`. -/
def dIdot_dt_4D (e f g P_0 lam_sim r_lrsc lam_lucid c H_max I_erase epsH epsI : ℝ)
    (s : ExistenceState) : ℝ :=
  e * Real.tanh (s.I_dot / epsI) * (dHobs_dt_4D c H_max I_erase epsH s) +
    f * (P_eff P_0 lam_sim r_lrsc lam_lucid s) - g * s.I_dot

/-- Smooth (`C^∞`) quadratic self-feedback ratio:
`R_self_sq(s) = fb(s)^2 / (fb(s)^2 + (f * P_0)^2 + sigma_0^2)`, where
`fb(s) = e * tanh(İ / ε_I) * dH_obs/dt` and `sigma_0 > 0` guarantees smoothness for all `P_0 ≥ 0`. -/
def R_self_sq (e f P_0 sigma_0 c H_max I_erase epsH epsI : ℝ) (s : ExistenceState) : ℝ :=
  let fb := e * Real.tanh (s.I_dot / epsI) * (dHobs_dt_4D c H_max I_erase epsH s)
  (fb ^ 2) / (fb ^ 2 + (f * P_0) ^ 2 + sigma_0 ^ 2)

/-- Eq. (B.4): Slow-memory / self-feedback readout (`Ψ`) dynamics with
the explicit state-dependent smooth quadratic ratio `R_self_sq`:
`dΨ/dt = κ_meta * R_self_sq(s) * (1 - Ψ) - μ_Ψ * Ψ`. -/
def dPsi_dt_4D (kappa_meta mu_Psi e f P_0 sigma_0 c H_max I_erase epsH epsI : ℝ)
    (s : ExistenceState) : ℝ :=
  kappa_meta * (R_self_sq e f P_0 sigma_0 c H_max I_erase epsH epsI s) * (1 - s.Psi) - mu_Psi * s.Psi

/-- Maximum entropy-rate magnitude bound `M_H_4D = c γ_max H_max + İ_erase`. -/
def M_H_4D (c gamma_max H_max I_erase : ℝ) : ℝ :=
  c * gamma_max * H_max + I_erase

/-- Upper processing ceiling `İ_max_4D = (e M_H_4D + f P_eff_max) / g` of the 4D box `B_4`. -/
def I_dot_max_4D (e f g P_0 lam_sim r_lrsc lam_lucid c gamma_max H_max I_erase : ℝ) : ℝ :=
  (e * M_H_4D c gamma_max H_max I_erase + f * P_eff_max P_0 lam_sim r_lrsc gamma_max lam_lucid) / g

/-- Unified 4D vector field `F_exist : ExistenceState → ExistenceState`. -/
def F_exist (a b c e f g gamma_max H_max E_avail P_0 sigma_0 lam_sim r_lrsc lam_lucid
    I_erase epsH epsI kappa_meta mu_Psi : ℝ) (s : ExistenceState) : ExistenceState :=
  { gamma := dgamma_dt_4D a b E_avail gamma_max s
  , H_obs := dHobs_dt_4D c H_max I_erase epsH s
  , I_dot := dIdot_dt_4D e f g P_0 lam_sim r_lrsc lam_lucid c H_max I_erase epsH epsI s
  , Psi   := dPsi_dt_4D kappa_meta mu_Psi e f P_0 sigma_0 c H_max I_erase epsH epsI s }

/-- Theorem B.0 (Unconditional Non-Negativity of State-Dependent `R_self_sq`):
For all real parameters and every state `s : ExistenceState`, `0 ≤ R_self_sq ... s`. -/
theorem R_self_sq_nonneg
    (e f P_0 sigma_0 c H_max I_erase epsH epsI : ℝ) (s : ExistenceState) :
    0 ≤ R_self_sq e f P_0 sigma_0 c H_max I_erase epsH epsI s := by
  unfold R_self_sq
  dsimp only
  have h_num : 0 ≤ (e * Real.tanh (s.I_dot / epsI) * dHobs_dt_4D c H_max I_erase epsH s) ^ 2 :=
    sq_nonneg _
  have h_den1 : 0 ≤ (e * Real.tanh (s.I_dot / epsI) * dHobs_dt_4D c H_max I_erase epsH s) ^ 2 + (f * P_0) ^ 2 :=
    add_nonneg h_num (sq_nonneg _)
  have h_den : 0 ≤ (e * Real.tanh (s.I_dot / epsI) * dHobs_dt_4D c H_max I_erase epsH s) ^ 2 + (f * P_0) ^ 2 + sigma_0 ^ 2 :=
    add_nonneg h_den1 (sq_nonneg _)
  exact div_nonneg h_num h_den

/-- Theorem B.1 (Face 1 — Lower γ-Boundary Condition, γ = 0): -/
theorem dgamma_dt_4D_nonneg_at_boundary
    (a b E_avail gamma_max : ℝ) (ha : 0 ≤ a) (hE : 0 ≤ E_avail)
    (s : ExistenceState) (hgamma : s.gamma = 0) (hI : 0 ≤ s.I_dot) :
    0 ≤ dgamma_dt_4D a b E_avail gamma_max s := by
  unfold dgamma_dt_4D
  rw [hgamma, zero_div, sub_zero, mul_one, mul_zero, sub_zero]
  exact mul_nonneg (mul_nonneg ha hI) hE

/-- Theorem B.1b (Pointwise Linear Decay Lower Bound for γ on `B_4`):
For any state `s` in the box (`0 ≤ s.I_dot`, `s.gamma ≤ gamma_max`, `0 < gamma_max`), the production
term `a * s.I_dot * E_avail * (1 - s.gamma / gamma_max)` is non-negative, so `-(b * s.gamma) ≤ dgamma_dt_4D`. -/
theorem dgamma_dt_4D_ge_neg_decay
    (a b E_avail gamma_max : ℝ)
    (ha : 0 ≤ a) (hE : 0 ≤ E_avail) (hgmax : 0 < gamma_max)
    (s : ExistenceState) (hI : 0 ≤ s.I_dot) (hgamma_le : s.gamma ≤ gamma_max) :
    -(b * s.gamma) ≤ dgamma_dt_4D a b E_avail gamma_max s := by
  unfold dgamma_dt_4D
  have h_div_le : s.gamma / gamma_max ≤ 1 := (div_le_one hgmax).mpr hgamma_le
  have h_one_sub : 0 ≤ 1 - s.gamma / gamma_max := sub_nonneg.mpr h_div_le
  have h_prod1 : 0 ≤ a * s.I_dot := mul_nonneg ha hI
  have h_prod2 : 0 ≤ a * s.I_dot * E_avail := mul_nonneg h_prod1 hE
  have h_prod3 : 0 ≤ a * s.I_dot * E_avail * (1 - s.gamma / gamma_max) :=
    mul_nonneg h_prod2 h_one_sub
  linarith

/-- Theorem B.2 (Face 2 — Upper γ-Ceiling Condition, γ = γ_max): -/
theorem dgamma_dt_4D_neg_at_ceiling
    (a b E_avail gamma_max : ℝ) (hb : 0 < b) (hgmax : 0 < gamma_max)
    (s : ExistenceState) (hgamma : s.gamma = gamma_max) :
    dgamma_dt_4D a b E_avail gamma_max s < 0 := by
  unfold dgamma_dt_4D
  have hdiv : gamma_max / gamma_max = 1 := div_self (ne_of_gt hgmax)
  rw [hgamma, hdiv, sub_self, mul_zero, zero_sub]
  exact neg_lt_zero.mpr (mul_pos hb hgmax)

/-- Theorem B.3 (Face 3 — Lower H_obs-Boundary Condition, H_obs = 0): -/
theorem dHobs_dt_4D_nonneg_at_boundary
    (c H_max I_erase epsH : ℝ) (hc : 0 ≤ c) (hHmax : 0 ≤ H_max)
    (s : ExistenceState) (hH : s.H_obs = 0) (hgamma : 0 ≤ s.gamma) :
    0 ≤ dHobs_dt_4D c H_max I_erase epsH s := by
  unfold dHobs_dt_4D
  rw [hH, zero_div, Real.tanh_zero, mul_zero, sub_zero, sub_zero]
  exact mul_nonneg (mul_nonneg hc hgamma) hHmax

/-- Theorem B.4 (Face 4 — Upper H_obs-Ceiling Condition, H_obs = H_max): -/
theorem dHobs_dt_4D_neg_at_ceiling
    (c H_max I_erase epsH : ℝ) (hIe : 0 < I_erase) (htanh : 0 < Real.tanh (H_max / epsH))
    (s : ExistenceState) (hH : s.H_obs = H_max) :
    dHobs_dt_4D c H_max I_erase epsH s < 0 := by
  unfold dHobs_dt_4D
  rw [hH, sub_self, mul_zero, zero_sub]
  exact neg_lt_zero.mpr (mul_pos hIe htanh)

/-- Lemma B.5a (Positivity of Effective Flux `P_eff` for `P_0 > 0`): -/
theorem P_eff_pos_on_box
    (P_0 lam_sim r_lrsc lam_lucid : ℝ)
    (hP0 : 0 < P_0) (hsim : 0 ≤ lam_sim) (hr : 0 ≤ r_lrsc) (hluc : 0 ≤ lam_lucid)
    (s : ExistenceState) (hgamma : 0 ≤ s.gamma) (hPsi : 0 ≤ s.Psi) :
    0 < P_eff P_0 lam_sim r_lrsc lam_lucid s := by
  unfold P_eff
  have h1 : 0 ≤ lam_sim * r_lrsc := mul_nonneg hsim hr
  have h2 : 0 ≤ lam_sim * r_lrsc * s.gamma := mul_nonneg h1 hgamma
  have h3 : 0 ≤ lam_lucid * s.Psi := mul_nonneg hluc hPsi
  linarith

/-- Theorem B.5 (Face 5 — Lower İ-Boundary Strict Positivity for `P_0 > 0`, İ = 0): -/
theorem dIdot_dt_4D_pos_at_boundary
    (e f g P_0 lam_sim r_lrsc lam_lucid c H_max I_erase epsH epsI : ℝ)
    (hf : 0 < f) (hP0 : 0 < P_0) (hsim : 0 ≤ lam_sim) (hr : 0 ≤ r_lrsc) (hluc : 0 ≤ lam_lucid)
    (s : ExistenceState) (hI : s.I_dot = 0) (hgamma : 0 ≤ s.gamma) (hPsi : 0 ≤ s.Psi) :
    0 < dIdot_dt_4D e f g P_0 lam_sim r_lrsc lam_lucid c H_max I_erase epsH epsI s := by
  unfold dIdot_dt_4D
  rw [hI, zero_div, Real.tanh_zero, mul_zero, zero_mul, zero_add, mul_zero, sub_zero]
  have hPeff : 0 < P_eff P_0 lam_sim r_lrsc lam_lucid s :=
    P_eff_pos_on_box P_0 lam_sim r_lrsc lam_lucid hP0 hsim hr hluc s hgamma hPsi
  exact mul_pos hf hPeff

/-- Theorem B.5b (Face 5 Zero-Drive Extension — Non-Negativity for `P_0 ≥ 0`, including `P_0 = 0`): -/
theorem dIdot_dt_4D_nonneg_at_boundary_zero_drive
    (e f g P_0 lam_sim r_lrsc lam_lucid c H_max I_erase epsH epsI : ℝ)
    (hf : 0 ≤ f) (hP0 : 0 ≤ P_0) (hsim : 0 ≤ lam_sim) (hr : 0 ≤ r_lrsc) (hluc : 0 ≤ lam_lucid)
    (s : ExistenceState) (hI : s.I_dot = 0) (hgamma : 0 ≤ s.gamma) (hPsi : 0 ≤ s.Psi) :
    0 ≤ dIdot_dt_4D e f g P_0 lam_sim r_lrsc lam_lucid c H_max I_erase epsH epsI s := by
  unfold dIdot_dt_4D P_eff
  rw [hI, zero_div, Real.tanh_zero, mul_zero, zero_mul, zero_add, mul_zero, sub_zero]
  have h1 : 0 ≤ lam_sim * r_lrsc := mul_nonneg hsim hr
  have h2 : 0 ≤ lam_sim * r_lrsc * s.gamma := mul_nonneg h1 hgamma
  have h3 : 0 ≤ lam_lucid * s.Psi := mul_nonneg hluc hPsi
  have h4 : 0 ≤ P_0 + lam_sim * r_lrsc * s.gamma + lam_lucid * s.Psi := by linarith
  exact mul_nonneg hf h4

/-- Lemma B.6a (Derived Entropy-Rate Upper Bound `dHobs_dt_4D ≤ M_H_4D` on the Box): -/
theorem dHobs_dt_4D_le_M_H
    (c gamma_max H_max I_erase epsH : ℝ)
    (hc : 0 ≤ c) (hHmax : 0 ≤ H_max) (hIe : 0 ≤ I_erase)
    (s : ExistenceState)
    (hgamma_nonneg : 0 ≤ s.gamma) (hgamma_le : s.gamma ≤ gamma_max)
    (hH_nonneg : 0 ≤ s.H_obs)
    (htanh_H_nonneg : 0 ≤ Real.tanh (s.H_obs / epsH)) :
    dHobs_dt_4D c H_max I_erase epsH s ≤ M_H_4D c gamma_max H_max I_erase := by
  unfold dHobs_dt_4D M_H_4D
  have hc_gamma_nonneg : 0 ≤ c * s.gamma := mul_nonneg hc hgamma_nonneg
  have h1 : H_max - s.H_obs ≤ H_max := sub_le_self H_max hH_nonneg
  have h_step1 : c * s.gamma * (H_max - s.H_obs) ≤ c * s.gamma * H_max :=
    mul_le_mul_of_nonneg_left h1 hc_gamma_nonneg
  have h2 : c * s.gamma ≤ c * gamma_max := mul_le_mul_of_nonneg_left hgamma_le hc
  have h_step2 : c * s.gamma * H_max ≤ c * gamma_max * H_max :=
    mul_le_mul_of_nonneg_right h2 hHmax
  have h4 : 0 ≤ I_erase * Real.tanh (s.H_obs / epsH) := mul_nonneg hIe htanh_H_nonneg
  linarith

/-- Lemma B.6a' (Derived Entropy-Rate Lower Bound `-M_H_4D ≤ dHobs_dt_4D` on the Box):
On `B_4` (`0 ≤ s.gamma`, `s.H_obs ≤ H_max`, `Real.tanh (s.H_obs / epsH) ≤ 1`), the production term
`c * s.gamma * (H_max - s.H_obs)` is non-negative and the erasure sink is at most `I_erase ≤ M_H_4D`,
so `-M_H_4D ≤ -I_erase ≤ dHobs_dt_4D`. -/
theorem dHobs_dt_4D_ge_neg_M_H
    (c gamma_max H_max I_erase epsH : ℝ)
    (hc : 0 ≤ c) (hgmax : 0 ≤ gamma_max) (hHmax : 0 ≤ H_max) (hIe : 0 ≤ I_erase)
    (s : ExistenceState)
    (hgamma_nonneg : 0 ≤ s.gamma) (hH_le : s.H_obs ≤ H_max)
    (htanh_H_le_one : Real.tanh (s.H_obs / epsH) ≤ 1) :
    -M_H_4D c gamma_max H_max I_erase ≤ dHobs_dt_4D c H_max I_erase epsH s := by
  unfold dHobs_dt_4D M_H_4D
  have hc_gamma : 0 ≤ c * s.gamma := mul_nonneg hc hgamma_nonneg
  have hH_sub : 0 ≤ H_max - s.H_obs := sub_nonneg.mpr hH_le
  have h_prod : 0 ≤ c * s.gamma * (H_max - s.H_obs) := mul_nonneg hc_gamma hH_sub
  have h_erase : I_erase * Real.tanh (s.H_obs / epsH) ≤ I_erase * 1 :=
    mul_le_mul_of_nonneg_left htanh_H_le_one hIe
  have h_cmax : 0 ≤ c * gamma_max * H_max := mul_nonneg (mul_nonneg hc hgmax) hHmax
  linarith

/-- Theorem B.5c (Uniform Linear Comparison Lower Bound on `dIdot_dt_4D` for `liminf İ > 0`):
Using `0 ≤ tanh(İ / ε_I) ≤ İ / ε_I` and `-M_H_4D ≤ dHobs_dt_4D` on `B_4`, the processing rate obeys
`f P_0 - e ((İ / ε_I) M_H_4D) - g İ ≤ dIdot_dt_4D`, supplying the uniform linear differential lower
bound that forces `liminf_{t → ∞} İ(t) ≥ f P_0 / (g + e M_H_4D / ε_I) > 0` whenever `P_0 > 0`.
Proved via explicit `mul_add`, `mul_assoc`, and `mul_le_mul_of_nonneg_left`/`right` without `nlinarith`. -/
theorem dIdot_dt_4D_ge_linear_floor
    (e f g P_0 lam_sim r_lrsc lam_lucid c gamma_max H_max I_erase epsH epsI : ℝ)
    (hc : 0 ≤ c) (he : 0 ≤ e) (hf : 0 ≤ f)
    (hgmax : 0 ≤ gamma_max) (hHmax : 0 ≤ H_max) (hIe : 0 ≤ I_erase)
    (hsim : 0 ≤ lam_sim) (hr : 0 ≤ r_lrsc) (hluc : 0 ≤ lam_lucid)
    (hMH : 0 ≤ M_H_4D c gamma_max H_max I_erase)
    (s : ExistenceState)
    (hgamma_nonneg : 0 ≤ s.gamma) (hH_le : s.H_obs ≤ H_max) (hPsi_nonneg : 0 ≤ s.Psi)
    (htanh_H_le_one : Real.tanh (s.H_obs / epsH) ≤ 1)
    (htanh_I_nonneg : 0 ≤ Real.tanh (s.I_dot / epsI))
    (htanh_I_le_lin : Real.tanh (s.I_dot / epsI) ≤ s.I_dot / epsI) :
    f * P_0 - e * ((s.I_dot / epsI) * M_H_4D c gamma_max H_max I_erase) - g * s.I_dot ≤
      dIdot_dt_4D e f g P_0 lam_sim r_lrsc lam_lucid c H_max I_erase epsH epsI s := by
  have hdH_lo : -M_H_4D c gamma_max H_max I_erase ≤ dHobs_dt_4D c H_max I_erase epsH s :=
    dHobs_dt_4D_ge_neg_M_H c gamma_max H_max I_erase epsH hc hgmax hHmax hIe s
      hgamma_nonneg hH_le htanh_H_le_one
  have h_Peff_lo : P_0 ≤ P_eff P_0 lam_sim r_lrsc lam_lucid s := by
    unfold P_eff
    have h_sr : 0 ≤ lam_sim * r_lrsc := mul_nonneg hsim hr
    have h_gam_term : 0 ≤ lam_sim * r_lrsc * s.gamma := mul_nonneg h_sr hgamma_nonneg
    have h_psi_term : 0 ≤ lam_lucid * s.Psi := mul_nonneg hluc hPsi_nonneg
    linarith
  unfold dIdot_dt_4D
  have hdH_sum : 0 ≤ dHobs_dt_4D c H_max I_erase epsH s + M_H_4D c gamma_max H_max I_erase := by
    linarith
  have h_step1 :
      0 ≤ Real.tanh (s.I_dot / epsI) *
        (dHobs_dt_4D c H_max I_erase epsH s + M_H_4D c gamma_max H_max I_erase) :=
    mul_nonneg htanh_I_nonneg hdH_sum
  have h_dist1 :
      Real.tanh (s.I_dot / epsI) *
        (dHobs_dt_4D c H_max I_erase epsH s + M_H_4D c gamma_max H_max I_erase) =
      Real.tanh (s.I_dot / epsI) * dHobs_dt_4D c H_max I_erase epsH s +
        Real.tanh (s.I_dot / epsI) * M_H_4D c gamma_max H_max I_erase :=
    mul_add (Real.tanh (s.I_dot / epsI))
      (dHobs_dt_4D c H_max I_erase epsH s) (M_H_4D c gamma_max H_max I_erase)
  have h_step2 :
      Real.tanh (s.I_dot / epsI) * M_H_4D c gamma_max H_max I_erase ≤
      (s.I_dot / epsI) * M_H_4D c gamma_max H_max I_erase :=
    mul_le_mul_of_nonneg_right htanh_I_le_lin hMH
  have h_step3 :
      0 ≤ Real.tanh (s.I_dot / epsI) * dHobs_dt_4D c H_max I_erase epsH s +
        (s.I_dot / epsI) * M_H_4D c gamma_max H_max I_erase := by
    linarith
  have h_step4 :
      0 ≤ e * (Real.tanh (s.I_dot / epsI) * dHobs_dt_4D c H_max I_erase epsH s +
        (s.I_dot / epsI) * M_H_4D c gamma_max H_max I_erase) :=
    mul_nonneg he h_step3
  have h_dist2 :
      e * (Real.tanh (s.I_dot / epsI) * dHobs_dt_4D c H_max I_erase epsH s +
        (s.I_dot / epsI) * M_H_4D c gamma_max H_max I_erase) =
      e * (Real.tanh (s.I_dot / epsI) * dHobs_dt_4D c H_max I_erase epsH s) +
        e * ((s.I_dot / epsI) * M_H_4D c gamma_max H_max I_erase) :=
    mul_add e
      (Real.tanh (s.I_dot / epsI) * dHobs_dt_4D c H_max I_erase epsH s)
      ((s.I_dot / epsI) * M_H_4D c gamma_max H_max I_erase)
  have h_assoc :
      e * Real.tanh (s.I_dot / epsI) * dHobs_dt_4D c H_max I_erase epsH s =
      e * (Real.tanh (s.I_dot / epsI) * dHobs_dt_4D c H_max I_erase epsH s) :=
    mul_assoc e (Real.tanh (s.I_dot / epsI)) (dHobs_dt_4D c H_max I_erase epsH s)
  have h_fPeff_lo : f * P_0 ≤ f * P_eff P_0 lam_sim r_lrsc lam_lucid s :=
    mul_le_mul_of_nonneg_left h_Peff_lo hf
  linarith

/-- Lemma B.6b (Upper Bound on Effective Flux `P_eff ≤ P_eff_max` on `B_4`): -/
theorem P_eff_le_P_eff_max
    (P_0 lam_sim r_lrsc gamma_max lam_lucid : ℝ)
    (hsim : 0 ≤ lam_sim) (hr : 0 ≤ r_lrsc) (hluc : 0 ≤ lam_lucid)
    (s : ExistenceState) (hgamma_le : s.gamma ≤ gamma_max) (hPsi_le : s.Psi ≤ 1) :
    P_eff P_0 lam_sim r_lrsc lam_lucid s ≤ P_eff_max P_0 lam_sim r_lrsc gamma_max lam_lucid := by
  unfold P_eff P_eff_max
  have h_sr_nonneg : 0 ≤ lam_sim * r_lrsc := mul_nonneg hsim hr
  have h_term1 : lam_sim * r_lrsc * s.gamma ≤ lam_sim * r_lrsc * gamma_max :=
    mul_le_mul_of_nonneg_left hgamma_le h_sr_nonneg
  have h_term2 : lam_lucid * s.Psi ≤ lam_lucid * 1 :=
    mul_le_mul_of_nonneg_left hPsi_le hluc
  linarith

/-- Theorem B.6 (Face 6 — Upper İ-Ceiling Condition with Derived `dHobs_dt_4D ≤ M_H_4D`, İ = İ_max_4D):
Here `dHobs_dt_4D ≤ M_H_4D` is derived internally from box membership (`0 ≤ s.gamma ≤ gamma_max`,
`0 ≤ s.H_obs`) via `dHobs_dt_4D_le_M_H`. -/
theorem dIdot_dt_4D_nonpos_at_ceiling
    (e f g P_0 lam_sim r_lrsc lam_lucid c gamma_max H_max I_erase epsH epsI : ℝ)
    (hc : 0 ≤ c) (he : 0 ≤ e) (hf : 0 ≤ f) (hg : 0 < g)
    (hHmax : 0 ≤ H_max) (hIe : 0 ≤ I_erase)
    (hsim : 0 ≤ lam_sim) (hr : 0 ≤ r_lrsc) (hluc : 0 ≤ lam_lucid)
    (hMH : 0 ≤ M_H_4D c gamma_max H_max I_erase)
    (s : ExistenceState)
    (hgamma_nonneg : 0 ≤ s.gamma) (hgamma_le : s.gamma ≤ gamma_max)
    (hH_nonneg : 0 ≤ s.H_obs) (hPsi_le : s.Psi ≤ 1)
    (hI : s.I_dot = I_dot_max_4D e f g P_0 lam_sim r_lrsc lam_lucid c gamma_max H_max I_erase)
    (htanh_H_nonneg : 0 ≤ Real.tanh (s.H_obs / epsH))
    (htanh_I_nonneg : 0 ≤ Real.tanh (s.I_dot / epsI))
    (htanh_I_le_one : Real.tanh (s.I_dot / epsI) ≤ 1) :
    dIdot_dt_4D e f g P_0 lam_sim r_lrsc lam_lucid c H_max I_erase epsH epsI s ≤ 0 := by
  have hdH : dHobs_dt_4D c H_max I_erase epsH s ≤ M_H_4D c gamma_max H_max I_erase :=
    dHobs_dt_4D_le_M_H c gamma_max H_max I_erase epsH hc hHmax hIe s
      hgamma_nonneg hgamma_le hH_nonneg htanh_H_nonneg
  unfold dIdot_dt_4D I_dot_max_4D at *
  have hg_ne : g ≠ 0 := ne_of_gt hg
  have h_g_mul :
      g * s.I_dot =
      e * M_H_4D c gamma_max H_max I_erase +
        f * P_eff_max P_0 lam_sim r_lrsc gamma_max lam_lucid := by
    rw [hI]
    exact mul_div_cancel₀
      (e * M_H_4D c gamma_max H_max I_erase +
        f * P_eff_max P_0 lam_sim r_lrsc gamma_max lam_lucid) hg_ne
  have h_step1 :
      Real.tanh (s.I_dot / epsI) * dHobs_dt_4D c H_max I_erase epsH s ≤
      Real.tanh (s.I_dot / epsI) * M_H_4D c gamma_max H_max I_erase :=
    mul_le_mul_of_nonneg_left hdH htanh_I_nonneg
  have h_step2 :
      Real.tanh (s.I_dot / epsI) * M_H_4D c gamma_max H_max I_erase ≤
      1 * M_H_4D c gamma_max H_max I_erase :=
    mul_le_mul_of_nonneg_right htanh_I_le_one hMH
  have h_step3 :
      Real.tanh (s.I_dot / epsI) * dHobs_dt_4D c H_max I_erase epsH s ≤
      M_H_4D c gamma_max H_max I_erase := by
    linarith
  have h_step4 :
      e * (Real.tanh (s.I_dot / epsI) * dHobs_dt_4D c H_max I_erase epsH s) ≤
      e * M_H_4D c gamma_max H_max I_erase :=
    mul_le_mul_of_nonneg_left h_step3 he
  have h_assoc :
      e * Real.tanh (s.I_dot / epsI) * dHobs_dt_4D c H_max I_erase epsH s =
      e * (Real.tanh (s.I_dot / epsI) * dHobs_dt_4D c H_max I_erase epsH s) :=
    mul_assoc e (Real.tanh (s.I_dot / epsI)) (dHobs_dt_4D c H_max I_erase epsH s)
  have h_P_bound :
      P_eff P_0 lam_sim r_lrsc lam_lucid s ≤
      P_eff_max P_0 lam_sim r_lrsc gamma_max lam_lucid :=
    P_eff_le_P_eff_max P_0 lam_sim r_lrsc gamma_max lam_lucid hsim hr hluc s hgamma_le hPsi_le
  have h_fP_bound :
      f * P_eff P_0 lam_sim r_lrsc lam_lucid s ≤
      f * P_eff_max P_0 lam_sim r_lrsc gamma_max lam_lucid :=
    mul_le_mul_of_nonneg_left h_P_bound hf
  linarith

/-- Theorem B.7 (Face 7 — Lower Ψ-Boundary Condition with State-Dependent `R_self_sq`, Ψ = 0): -/
theorem dPsi_dt_4D_nonneg_at_boundary
    (kappa_meta mu_Psi e f P_0 sigma_0 c H_max I_erase epsH epsI : ℝ)
    (hkappa : 0 ≤ kappa_meta)
    (s : ExistenceState) (hPsi : s.Psi = 0) :
    0 ≤ dPsi_dt_4D kappa_meta mu_Psi e f P_0 sigma_0 c H_max I_erase epsH epsI s := by
  unfold dPsi_dt_4D
  rw [hPsi, sub_zero, mul_one, mul_zero, sub_zero]
  have hR : 0 ≤ R_self_sq e f P_0 sigma_0 c H_max I_erase epsH epsI s :=
    R_self_sq_nonneg e f P_0 sigma_0 c H_max I_erase epsH epsI s
  exact mul_nonneg hkappa hR

/-- Theorem B.8 (Face 8 — Upper Ψ-Ceiling Condition with State-Dependent `R_self_sq`, Ψ = 1): -/
theorem dPsi_dt_4D_neg_at_ceiling
    (kappa_meta mu_Psi e f P_0 sigma_0 c H_max I_erase epsH epsI : ℝ)
    (hmu : 0 < mu_Psi)
    (s : ExistenceState) (hPsi : s.Psi = 1) :
    dPsi_dt_4D kappa_meta mu_Psi e f P_0 sigma_0 c H_max I_erase epsH epsI s < 0 := by
  unfold dPsi_dt_4D
  rw [hPsi, sub_self, mul_zero, zero_sub, mul_one]
  exact neg_lt_zero.mpr hmu

/-- Theorem B.9 (Unified 8-Face 4D Box Pointwise Boundary Certificate):
Simultaneous formal verification of all eight pointwise boundary and ceiling sign conditions of
`B_4 = [0, γ_max] × [0, H_max] × [0, İ_max_4D] × [0, 1]` with the explicit state-dependent
smooth quadratic `R_self_sq` and derived `dHobs_dt_4D ≤ M_H_4D`. -/
theorem existence_box_8face_nagumo_certificate
    (a b c e f g gamma_max H_max E_avail P_0 sigma_0 lam_sim r_lrsc lam_lucid
     I_erase epsH epsI kappa_meta mu_Psi : ℝ)
    (ha : 0 ≤ a) (hb : 0 < b) (hc : 0 ≤ c) (he : 0 ≤ e) (hf : 0 < f) (hg : 0 < g)
    (hgmax : 0 < gamma_max) (hHmax : 0 < H_max) (hE : 0 ≤ E_avail) (hP0 : 0 < P_0)
    (hsim : 0 ≤ lam_sim) (hr : 0 ≤ r_lrsc) (hluc : 0 ≤ lam_lucid)
    (hIe : 0 < I_erase) (htanh_Hmax : 0 < Real.tanh (H_max / epsH))
    (hMH : 0 ≤ M_H_4D c gamma_max H_max I_erase)
    (hkappa : 0 ≤ kappa_meta) (hmu : 0 < mu_Psi) :
    -- Face 1: Lower γ-boundary (γ = 0)
    (∀ s : ExistenceState, s.gamma = 0 → 0 ≤ s.I_dot →
      0 ≤ (F_exist a b c e f g gamma_max H_max E_avail P_0 sigma_0 lam_sim r_lrsc lam_lucid
            I_erase epsH epsI kappa_meta mu_Psi s).gamma) ∧
    -- Face 2: Upper γ-ceiling (γ = γ_max)
    (∀ s : ExistenceState, s.gamma = gamma_max →
      (F_exist a b c e f g gamma_max H_max E_avail P_0 sigma_0 lam_sim r_lrsc lam_lucid
        I_erase epsH epsI kappa_meta mu_Psi s).gamma < 0) ∧
    -- Face 3: Lower H_obs-boundary (H_obs = 0)
    (∀ s : ExistenceState, s.H_obs = 0 → 0 ≤ s.gamma →
      0 ≤ (F_exist a b c e f g gamma_max H_max E_avail P_0 sigma_0 lam_sim r_lrsc lam_lucid
            I_erase epsH epsI kappa_meta mu_Psi s).H_obs) ∧
    -- Face 4: Upper H_obs-ceiling (H_obs = H_max)
    (∀ s : ExistenceState, s.H_obs = H_max →
      (F_exist a b c e f g gamma_max H_max E_avail P_0 sigma_0 lam_sim r_lrsc lam_lucid
        I_erase epsH epsI kappa_meta mu_Psi s).H_obs < 0) ∧
    -- Face 5: Lower İ-boundary (İ = 0)
    (∀ s : ExistenceState, s.I_dot = 0 → 0 ≤ s.gamma → 0 ≤ s.Psi →
      0 < (F_exist a b c e f g gamma_max H_max E_avail P_0 sigma_0 lam_sim r_lrsc lam_lucid
            I_erase epsH epsI kappa_meta mu_Psi s).I_dot) ∧
    -- Face 6: Upper İ-ceiling (İ = İ_max_4D, with dHobs_dt_4D ≤ M_H_4D derived from box membership)
    (∀ s : ExistenceState,
      0 ≤ s.gamma → s.gamma ≤ gamma_max → 0 ≤ s.H_obs → s.Psi ≤ 1 →
      s.I_dot = I_dot_max_4D e f g P_0 lam_sim r_lrsc lam_lucid c gamma_max H_max I_erase →
      0 ≤ Real.tanh (s.H_obs / epsH) →
      0 ≤ Real.tanh (s.I_dot / epsI) →
      Real.tanh (s.I_dot / epsI) ≤ 1 →
      (F_exist a b c e f g gamma_max H_max E_avail P_0 sigma_0 lam_sim r_lrsc lam_lucid
        I_erase epsH epsI kappa_meta mu_Psi s).I_dot ≤ 0) ∧
    -- Face 7: Lower Ψ-boundary (Ψ = 0, state-dependent R_self_sq ≥ 0 derived automatically)
    (∀ s : ExistenceState, s.Psi = 0 →
      0 ≤ (F_exist a b c e f g gamma_max H_max E_avail P_0 sigma_0 lam_sim r_lrsc lam_lucid
            I_erase epsH epsI kappa_meta mu_Psi s).Psi) ∧
    -- Face 8: Upper Ψ-ceiling (Ψ = 1)
    (∀ s : ExistenceState, s.Psi = 1 →
      (F_exist a b c e f g gamma_max H_max E_avail P_0 sigma_0 lam_sim r_lrsc lam_lucid
        I_erase epsH epsI kappa_meta mu_Psi s).Psi < 0) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro s hgamma hI
    exact dgamma_dt_4D_nonneg_at_boundary a b E_avail gamma_max ha hE s hgamma hI
  · intro s hgamma
    exact dgamma_dt_4D_neg_at_ceiling a b E_avail gamma_max hb hgmax s hgamma
  · intro s hH hgamma
    exact dHobs_dt_4D_nonneg_at_boundary c H_max I_erase epsH hc (le_of_lt hHmax) s hH hgamma
  · intro s hH
    exact dHobs_dt_4D_neg_at_ceiling c H_max I_erase epsH hIe htanh_Hmax s hH
  · intro s hI hgamma hPsi
    exact dIdot_dt_4D_pos_at_boundary e f g P_0 lam_sim r_lrsc lam_lucid c H_max I_erase epsH epsI
      hf hP0 hsim hr hluc s hI hgamma hPsi
  · intro s hgamma_nonneg hgamma_le hH_nonneg hPsi_le hI htH htI0 htI1
    exact dIdot_dt_4D_nonpos_at_ceiling e f g P_0 lam_sim r_lrsc lam_lucid c gamma_max H_max
      I_erase epsH epsI hc he (le_of_lt hf) hg (le_of_lt hHmax) (le_of_lt hIe) hsim hr hluc hMH
      s hgamma_nonneg hgamma_le hH_nonneg hPsi_le hI htH htI0 htI1
  · intro s hPsi
    exact dPsi_dt_4D_nonneg_at_boundary kappa_meta mu_Psi e f P_0 sigma_0 c H_max I_erase
      epsH epsI hkappa s hPsi
  · intro s hPsi
    exact dPsi_dt_4D_neg_at_ceiling kappa_meta mu_Psi e f P_0 sigma_0 c H_max I_erase
      epsH epsI hmu s hPsi

#print axioms R_self_sq_nonneg
#print axioms dgamma_dt_4D_ge_neg_decay
#print axioms dHobs_dt_4D_ge_neg_M_H
#print axioms dIdot_dt_4D_ge_linear_floor
#print axioms dIdot_dt_4D_nonneg_at_boundary_zero_drive
#print axioms existence_box_8face_nagumo_certificate

end
