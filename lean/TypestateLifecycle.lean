import Mathlib.Tactic.Linarith
import Mathlib.Data.Real.Basic

/-!
# Formal Request-Lifecycle Typestate Trace Invariants, Worker-Epoch Isolation,
# Real Patankar-Euler Positivity, Pointwise Capacitive Decay Bound, Perturbation Budget Scaling,
# Sequence Monotonicity, and Merkle-DAG Join-Semilattice (`TypestateLifecycle.lean`)

Author: Prince Upadhyay (ORCID: 0009-0002-1170-4487)
Version: 1.3.2 (Concept DOI: 10.5281/zenodo.23618032)
License: MIT License

## Scope & Claim Boundary (`does_not_imply`)
This module machine-checks sixteen formal properties of the Shark Protocol's mathematical models
with zero `sorry` axioms and zero `nlinarith` heuristics:
1. Six theorems (`oom_from_partial_init_is_poisoned`, `no_deref_after_partial_oom_abort`,
   `no_shutdown_uaf_on_poisoned_state`, `stale_epoch_read_rejected`,
   `typestate_and_epoch_security_certificate`, and `sealed_active_unique_trace_from_uninit`)
   formalizing a 6-state request-lifecycle typestate automaton (where `ZeroedFreed` is strictly
   absorbing, `{AbortedPoisoned, ZeroedFreed}` forms a closed terminal sink across all finite
   event traces `evs : List LifecycleEvent`, and `SealedActive` is reachable from `Uninit` if and
   only if `evs = [BeginInit, SealSuccess]`) and a worker-epoch guard (`slotEpoch = workerEpoch`).
2. Three theorems over `ℝ` and `Nat` addressing real-arithmetic Patankar-Euler step
   box bounds (`patankar_euler_step_in_box`), the pointwise differential lower bound
   `dΨ/dt ≥ -μ_Ψ * Ψ` (`psi_decay_floor_bound`), and pairwise Merkle-DAG parent-pair commutativity
   (`merkle_dag_merge_commutative`).
3. Four theorems addressing real-arithmetic Patankar-Euler strict positivity
   (`patankar_strict_positivity_floor`), linear perturbation budget scaling
   (`perturbation_budget_scaling`), sequence counter strict monotonicity
   (`fence_seq_strict_monotonicity`), and N-way Merkle-DAG join-semilattice commutativity,
   associativity, and idempotence (`merkle_dag_semilattice_laws`).
4. Three theorems/lemmas covering outward-rounded interval containment
   (`patankar_interval_rounding_in_box`), a definitional projection lemma
   (`projection_independent_of_secret`), and two-step piecewise Duhamel contraction vs. single-horizon
   growth (`duhamel_piecewise_contraction_bound`).

**What is NOT claimed:**
- Theorems 6, 9, and 13 are proved over the mathematical real field `ℝ` (which has no subnormal numbers);
  IEEE-754 float64 subnormal clamping at `FLOAT64_NORMAL_MIN` and 200-bit `mpmath.iv` interval checks are
  enforced in Python runtime code.
- Theorem 7 proves the pointwise derivative inequality `dΨ/dt ≥ -μ_Ψ * Ψ`; the integrated bound
  `Ψ(t + Δt) ≥ Ψ(t) * exp(-μ_Ψ * Δt)` follows analytically via the classical Grönwall lemma.
- Theorem 10 (`perturbation_budget_scaling`) proves the linear scaling inequality `0 ≤ L * η_⊥ ≤ L * τ_null`
  for an assumed non-negative sensitivity constant `L ≥ 0`; because dot-product softmax attention is not
  globally Lipschitz (Kim, Papamakarios & Mnih, ICML 2021), `L` is an explicit assumed local parameter.
- Theorem 14 (`projection_independent_of_secret`) is a definitional projection lemma showing that a pure
  function of `PublicLedgerState` does not depend on a separate `SignerPrincipalState` argument; OS process
  isolation rests on the runtime `subprocess.Popen` architecture and regression tests, not this lemma.
-/

namespace SharkProtocol

/-- Six-state request lifecycle automaton with absorbing terminal state `ZeroedFreed`. -/
inductive LifecycleState : Type
  | Uninit         : LifecycleState
  | PartialInit    : LifecycleState
  | SealedActive   : LifecycleState
  | ShutdownClean  : LifecycleState
  | AbortedPoisoned: LifecycleState
  | ZeroedFreed    : LifecycleState
  deriving DecidableEq, Repr

/-- Lifecycle transition events. -/
inductive LifecycleEvent : Type
  | BeginInit   : LifecycleEvent
  | SealSuccess : LifecycleEvent
  | OOMAbort    : LifecycleEvent
  | NormalClose : LifecycleEvent
  | ZeroAndFree : LifecycleEvent
  deriving DecidableEq, Repr

/-- Deterministic state transition function δ : LifecycleState → LifecycleEvent → LifecycleState.
    `ZeroedFreed` is strictly absorbing under all events, and `{AbortedPoisoned, ZeroedFreed}` is closed. -/
def stepLifecycle (s : LifecycleState) (ev : LifecycleEvent) : LifecycleState :=
  match s, ev with
  | LifecycleState.Uninit,          LifecycleEvent.BeginInit   => LifecycleState.PartialInit
  | LifecycleState.PartialInit,     LifecycleEvent.SealSuccess => LifecycleState.SealedActive
  | LifecycleState.PartialInit,     LifecycleEvent.OOMAbort    => LifecycleState.AbortedPoisoned
  | LifecycleState.SealedActive,    LifecycleEvent.OOMAbort    => LifecycleState.AbortedPoisoned
  | LifecycleState.SealedActive,    LifecycleEvent.NormalClose => LifecycleState.ShutdownClean
  | LifecycleState.ShutdownClean,   LifecycleEvent.ZeroAndFree => LifecycleState.ZeroedFreed
  | LifecycleState.AbortedPoisoned, LifecycleEvent.ZeroAndFree => LifecycleState.ZeroedFreed
  | LifecycleState.ZeroedFreed,     _                          => LifecycleState.ZeroedFreed
  | _,                              _                          => LifecycleState.AbortedPoisoned

/-- Canonical string name of a `LifecycleState` for JSON transition-table export (`#eval`). -/
def stateToString : LifecycleState → String
  | LifecycleState.Uninit          => "UNINIT"
  | LifecycleState.PartialInit     => "PARTIAL_INIT"
  | LifecycleState.SealedActive    => "SEALED_ACTIVE"
  | LifecycleState.ShutdownClean   => "SHUTDOWN_CLEAN"
  | LifecycleState.AbortedPoisoned => "ABORTED_POISONED"
  | LifecycleState.ZeroedFreed     => "ZEROED_FREED"

/-- Canonical string name of a `LifecycleEvent` for JSON transition-table export (`#eval`). -/
def eventToString : LifecycleEvent → String
  | LifecycleEvent.BeginInit   => "BEGIN_INIT"
  | LifecycleEvent.SealSuccess => "SEAL_SUCCESS"
  | LifecycleEvent.OOMAbort    => "OOM_ABORT"
  | LifecycleEvent.NormalClose => "NORMAL_CLOSE"
  | LifecycleEvent.ZeroAndFree => "ZERO_AND_FREE"

def allStates : List LifecycleState :=
  [LifecycleState.Uninit, LifecycleState.PartialInit, LifecycleState.SealedActive,
   LifecycleState.ShutdownClean, LifecycleState.AbortedPoisoned, LifecycleState.ZeroedFreed]

def allEvents : List LifecycleEvent :=
  [LifecycleEvent.BeginInit, LifecycleEvent.SealSuccess, LifecycleEvent.OOMAbort,
   LifecycleEvent.NormalClose, LifecycleEvent.ZeroAndFree]

/-- Export the complete 6x5 Lean transition table to a JSON string via `#eval`. -/
def dumpTransitionTableJson : String :=
  let rows := allStates.map (fun s =>
    let pairs := allEvents.map (fun ev =>
      "\"" ++ eventToString ev ++ "\":\"" ++ stateToString (stepLifecycle s ev) ++ "\"")
    "\"" ++ stateToString s ++ "\":{" ++ String.intercalate "," pairs ++ "}")
  "{" ++ String.intercalate "," rows ++ "}"

#eval dumpTransitionTableJson

/-- Multi-step trace execution fold over any finite list of lifecycle events. -/
def runTrace (s : LifecycleState) (evs : List LifecycleEvent) : LifecycleState :=
  match evs with
  | []        => s
  | ev :: rem => runTrace (stepLifecycle s ev) rem

/-- Predicate: payload dereferencing is permitted only in `SealedActive`. -/
def canDereferencePayload (s : LifecycleState) : Prop :=
  s = LifecycleState.SealedActive

/-- Predicate: normal destructor cleanup is permitted only in `ShutdownClean`. -/
def canRunCleanDestructor (s : LifecycleState) : Prop :=
  s = LifecycleState.ShutdownClean

/-- Worker slot tagged with a monotonically increasing request epoch. -/
structure WorkerSlot where
  slotEpoch   : Nat
  state       : LifecycleState
  isZeroed    : Bool
  deriving DecidableEq, Repr

/-- Predicate: a worker at `workerEpoch` may read `slot` iff epochs match, state is `SealedActive`, and buffer is not zeroed. -/
def canAccessWorkerSlot (workerEpoch : Nat) (slot : WorkerSlot) : Prop :=
  slot.slotEpoch = workerEpoch ∧ slot.state = LifecycleState.SealedActive ∧ slot.isZeroed = false

/-- Factored single-step sink closure helper for `{AbortedPoisoned, ZeroedFreed}`. -/
private def sink_step_closed : ∀ (s : LifecycleState) (e : LifecycleEvent),
    (s = LifecycleState.AbortedPoisoned ∨ s = LifecycleState.ZeroedFreed) →
    (stepLifecycle s e = LifecycleState.AbortedPoisoned ∨ stepLifecycle s e = LifecycleState.ZeroedFreed) := by
  intro s e hs
  cases hs with
  | inl h_ab =>
    rw [h_ab]
    cases e with
    | BeginInit   => exact Or.inl rfl
    | SealSuccess => exact Or.inl rfl
    | OOMAbort    => exact Or.inl rfl
    | NormalClose => exact Or.inl rfl
    | ZeroAndFree => exact Or.inr rfl
  | inr h_zf =>
    rw [h_zf]
    cases e <;> exact Or.inr rfl

/-- Factored multi-step trace sink closure helper for `{AbortedPoisoned, ZeroedFreed}`. -/
private def sink_trace_closed : ∀ (l : List LifecycleEvent) (s : LifecycleState),
    (s = LifecycleState.AbortedPoisoned ∨ s = LifecycleState.ZeroedFreed) →
    (runTrace s l = LifecycleState.AbortedPoisoned ∨ runTrace s l = LifecycleState.ZeroedFreed) := by
  intro l
  induction l with
  | nil =>
    intro s hs
    exact hs
  | cons hd tl ih =>
    intro s hs
    change runTrace (stepLifecycle s hd) tl = LifecycleState.AbortedPoisoned ∨
           runTrace (stepLifecycle s hd) tl = LifecycleState.ZeroedFreed
    exact ih (stepLifecycle s hd) (sink_step_closed s hd hs)

/-- Factored helper showing any trace starting in `{AbortedPoisoned, ZeroedFreed}` never reaches `SealedActive`. -/
private def sink_trace_ne_sealed (l : List LifecycleEvent) (s : LifecycleState)
    (hs : s = LifecycleState.AbortedPoisoned ∨ s = LifecycleState.ZeroedFreed) :
    runTrace s l ≠ LifecycleState.SealedActive := by
  intro h_eq
  have h_end := sink_trace_closed l s hs
  cases h_end with
  | inl h_ab =>
    rw [h_ab] at h_eq
    cases h_eq
  | inr h_zf =>
    rw [h_zf] at h_eq
    cases h_eq

/-- Factored helper showing any single step from `ShutdownClean` enters `{AbortedPoisoned, ZeroedFreed}`. -/
private def shutdown_step_in_sink (e : LifecycleEvent) :
    stepLifecycle LifecycleState.ShutdownClean e = LifecycleState.AbortedPoisoned ∨
    stepLifecycle LifecycleState.ShutdownClean e = LifecycleState.ZeroedFreed := by
  cases e with
  | BeginInit   => exact Or.inl rfl
  | SealSuccess => exact Or.inl rfl
  | OOMAbort    => exact Or.inl rfl
  | NormalClose => exact Or.inl rfl
  | ZeroAndFree => exact Or.inr rfl

/-- Theorem 1: An OOM abort during `PartialInit` transitions to `AbortedPoisoned`, and `ZeroedFreed`
    is a strictly absorbing terminal state across all single events `ev` and all finite traces `evs`. -/
theorem oom_from_partial_init_is_poisoned (ev : LifecycleEvent) (evs : List LifecycleEvent) :
    stepLifecycle LifecycleState.PartialInit LifecycleEvent.OOMAbort = LifecycleState.AbortedPoisoned ∧
    stepLifecycle LifecycleState.ZeroedFreed ev = LifecycleState.ZeroedFreed ∧
    runTrace LifecycleState.ZeroedFreed evs = LifecycleState.ZeroedFreed := by
  have h_step : ∀ e : LifecycleEvent, stepLifecycle LifecycleState.ZeroedFreed e = LifecycleState.ZeroedFreed := by
    intro e
    cases e <;> rfl
  have h_trace : ∀ l : List LifecycleEvent, runTrace LifecycleState.ZeroedFreed l = LifecycleState.ZeroedFreed := by
    intro l
    induction l with
    | nil => rfl
    | cons hd tl ih =>
      change runTrace (stepLifecycle LifecycleState.ZeroedFreed hd) tl = LifecycleState.ZeroedFreed
      rw [h_step hd]
      exact ih
  exact ⟨rfl, h_step ev, h_trace evs⟩

/-- Theorem 2: Inductive trace safety — after a partial-initialization OOM abort, payload dereferencing
    is ruled out not only at the immediate step but across all subsequent finite event traces `evs`. -/
theorem no_deref_after_partial_oom_abort (evs : List LifecycleEvent) :
    ¬ canDereferencePayload (stepLifecycle LifecycleState.PartialInit LifecycleEvent.OOMAbort) ∧
    ¬ canDereferencePayload (runTrace (stepLifecycle LifecycleState.PartialInit LifecycleEvent.OOMAbort) evs) := by
  constructor
  · intro h1
    cases h1
  · intro h_trace
    unfold canDereferencePayload at h_trace
    exact sink_trace_ne_sealed evs (stepLifecycle LifecycleState.PartialInit LifecycleEvent.OOMAbort) (Or.inl rfl) h_trace

/-- Theorem 3: Inductive trace safety — after a partial-initialization OOM abort, clean destructor
    execution is ruled out across the immediate state and all subsequent finite event traces `evs`. -/
theorem no_shutdown_uaf_on_poisoned_state (evs : List LifecycleEvent) :
    ¬ canRunCleanDestructor (stepLifecycle LifecycleState.PartialInit LifecycleEvent.OOMAbort) ∧
    ¬ canRunCleanDestructor (runTrace (stepLifecycle LifecycleState.PartialInit LifecycleEvent.OOMAbort) evs) := by
  constructor
  · intro h1
    cases h1
  · intro h_trace
    unfold canRunCleanDestructor at h_trace
    have h_end := sink_trace_closed evs (stepLifecycle LifecycleState.PartialInit LifecycleEvent.OOMAbort) (Or.inl rfl)
    cases h_end with
    | inl h_ab =>
      rw [h_ab] at h_trace
      cases h_trace
    | inr h_zf =>
      rw [h_zf] at h_trace
      cases h_trace

/-- Theorem 4: Any worker slot from a stale epoch (`slot.slotEpoch ≠ workerEpoch`) cannot be read. -/
theorem stale_epoch_read_rejected (workerEpoch : Nat) (slot : WorkerSlot)
    (h_stale : slot.slotEpoch ≠ workerEpoch) :
    ¬ canAccessWorkerSlot workerEpoch slot := by
  intro h_access
  exact h_stale h_access.1

/-- Theorem 5: Joint multi-step trace typestate, terminal absorbing `ZeroedFreed`, and worker-epoch certificate. -/
theorem typestate_and_epoch_security_certificate
    (workerEpoch : Nat) (slot : WorkerSlot) (ev : LifecycleEvent) (evs : List LifecycleEvent)
    (h_stale : slot.slotEpoch ≠ workerEpoch) :
    (stepLifecycle LifecycleState.PartialInit LifecycleEvent.OOMAbort = LifecycleState.AbortedPoisoned) ∧
    (runTrace LifecycleState.ZeroedFreed evs = LifecycleState.ZeroedFreed) ∧
    (¬ canDereferencePayload (runTrace (stepLifecycle LifecycleState.PartialInit LifecycleEvent.OOMAbort) evs)) ∧
    (¬ canRunCleanDestructor (runTrace (stepLifecycle LifecycleState.PartialInit LifecycleEvent.OOMAbort) evs)) ∧
    (¬ canAccessWorkerSlot workerEpoch slot) := by
  have h1 := oom_from_partial_init_is_poisoned ev evs
  have h2 := no_deref_after_partial_oom_abort evs
  have h3 := no_shutdown_uaf_on_poisoned_state evs
  refine ⟨h1.1, h1.2.2, h2.2, h3.2, stale_epoch_read_rejected workerEpoch slot h_stale⟩

/-- Theorem 6 (Real-Arithmetic Patankar-Euler Box Invariance):
    For any real state `x ∈ [0, x_max]`, step size `dt ≥ 0`, non-negative production weight `P ≥ 0`,
    and non-negative destruction weight `D ≥ 0`, the Patankar-Euler numerator `num = x + dt * P * x_max`
    and denominator `den = 1 + dt * (P + D)` satisfy `0 ≤ num` and `num ≤ x_max * den`. -/
theorem patankar_euler_step_in_box
    (x x_max dt P D : ℝ)
    (hx_lo : 0 ≤ x) (hx_hi : x ≤ x_max)
    (hdt : 0 ≤ dt) (hP : 0 ≤ P) (hD : 0 ≤ D) :
    0 ≤ x + dt * P * x_max ∧
    x + dt * P * x_max ≤ x_max * (1 + dt * (P + D)) := by
  have h_xmax_nonneg : 0 ≤ x_max := by linarith
  have h_dtP : 0 ≤ dt * P := mul_nonneg hdt hP
  have h_prod : 0 ≤ dt * P * x_max := mul_nonneg h_dtP h_xmax_nonneg
  have h_dtD : 0 ≤ dt * D := mul_nonneg hdt hD
  have h_dest : 0 ≤ dt * D * x_max := mul_nonneg h_dtD h_xmax_nonneg
  constructor
  · linarith
  · linarith

/-- Theorem 7 (Pointwise Differential Lower Bound on Self-Modeling Readout Velocity):
    Whenever `κ_meta ≥ 0`, `R_self ≥ 0`, and `Ψ ≤ 1`, the instantaneous derivative
    `dΨ/dt = κ_meta * R_self * (1 - Ψ) - μ_Ψ * Ψ` is bounded below by `-μ_Ψ * Ψ`.
    (Combined analytically with the classical Grönwall lemma, this yields `Ψ(t+Δt) ≥ Ψ(t)e^{-μ_Ψ Δt}`). -/
theorem psi_decay_floor_bound
    (kappa_meta R_self Psi mu_Psi : ℝ)
    (h_kap : 0 ≤ kappa_meta) (h_R : 0 ≤ R_self) (h_psi_hi : Psi ≤ 1) :
    -mu_Psi * Psi ≤ kappa_meta * R_self * (1 - Psi) - mu_Psi * Psi := by
  have h_one_minus : 0 ≤ 1 - Psi := by linarith
  have h_kapR : 0 ≤ kappa_meta * R_self := mul_nonneg h_kap h_R
  have h_prod : 0 ≤ kappa_meta * R_self * (1 - Psi) := mul_nonneg h_kapR h_one_minus
  linarith

/-- Canonical commutative parent-pair normalizer for Merkle-DAG split-brain branch merges. -/
def canonicalMergePair (hA hB : Nat) : Nat × Nat :=
  if hA ≤ hB then (hA, hB) else (hB, hA)

/-- Theorem 8 (Pairwise Merkle-DAG Join Commutativity):
    Canonical parent-pair ordering is strictly commutative (`canonicalMergePair hA hB = canonicalMergePair hB hA`). -/
theorem merkle_dag_merge_commutative (hA hB : Nat) :
    canonicalMergePair hA hB = canonicalMergePair hB hA := by
  unfold canonicalMergePair
  by_cases h1 : hA ≤ hB
  · by_cases h2 : hB ≤ hA
    · have h_eq : hA = hB := Nat.le_antisymm h1 h2
      simp [h_eq]
    · simp [h1, h2]
  · have h2 : hB ≤ hA := Nat.le_of_not_le h1
    simp [h1, h2]

/-- Theorem 9 (Real-Arithmetic Patankar Numerator & Denominator Strict Positivity):
    Over `ℝ`, whenever `0 < x`, `0 ≤ x_max`, `0 ≤ dt`, `0 ≤ P`, and `0 ≤ D`, the Patankar-Euler
    numerator satisfies `0 < x ≤ x + dt * P * x_max` and the denominator satisfies `1 ≤ 1 + dt * (P + D)`.
    (IEEE-754 float64 subnormal clamping at `FLOAT64_NORMAL_MIN` is enforced separately in Python). -/
theorem patankar_strict_positivity_floor
    (x x_max dt P D : ℝ)
    (hx_pos : 0 < x) (hx_max : 0 ≤ x_max)
    (hdt : 0 ≤ dt) (hP : 0 ≤ P) (hD : 0 ≤ D) :
    x ≤ x + dt * P * x_max ∧ 0 < x + dt * P * x_max ∧ 1 ≤ 1 + dt * (P + D) := by
  have h_dtP : 0 ≤ dt * P := mul_nonneg hdt hP
  have h_prod : 0 ≤ dt * P * x_max := mul_nonneg h_dtP hx_max
  have h_dtD : 0 ≤ dt * D := mul_nonneg hdt hD
  refine ⟨by linarith, by linarith, by linarith⟩

/-- Theorem 10 (Linear Perturbation Budget Scaling for Assumed Sensitivity Parameter `L_attn`):
    For any assumed non-negative local sensitivity factor `0 ≤ L_attn` and orthogonal residual
    ratio `0 ≤ eta_perp ≤ tau_null`, the scaled perturbation budget `L_attn * eta_perp` satisfies
    `0 ≤ L_attn * eta_perp ≤ L_attn * tau_null`. -/
theorem perturbation_budget_scaling
    (L_attn eta_perp tau_null : ℝ)
    (hL : 0 ≤ L_attn) (heta_lo : 0 ≤ eta_perp) (heta_hi : eta_perp ≤ tau_null) :
    0 ≤ L_attn * eta_perp ∧ L_attn * eta_perp ≤ L_attn * tau_null := by
  have h_nonneg : 0 ≤ L_attn * eta_perp := mul_nonneg hL heta_lo
  have h_diff_nonneg : 0 ≤ tau_null - eta_perp := by linarith
  have h_prod_diff : 0 ≤ L_attn * (tau_null - eta_perp) := mul_nonneg hL h_diff_nonneg
  constructor
  · exact h_nonneg
  · linarith

/-- Monotonic transition fence increment operator. -/
def stepFenceSeq (seq : ℝ) : ℝ := seq + 1

/-- Theorem 11 (Fence Sequence Increment Monotonicity):
    Every transition increment strictly advances a non-negative sequence number (`seq < stepFenceSeq seq`
    and `1 ≤ stepFenceSeq seq`). -/
theorem fence_seq_strict_monotonicity (seq : ℝ) (h_nonneg : 0 ≤ seq) :
    seq < stepFenceSeq seq ∧ 1 ≤ stepFenceSeq seq := by
  unfold stepFenceSeq
  constructor
  · linarith
  · linarith

/-- Canonical N-way Merkle-DAG digest-set join-semilattice union operator. -/
def dagJoinSet (A B : Nat → Prop) (d : Nat) : Prop :=
  A d ∨ B d

/-- Theorem 12 (N-Way Merkle-DAG Join-Semilattice Commutativity, Associativity & Idempotence):
    Reconciling multi-partition ledger claim sets via `dagJoinSet` forms a mathematical join-semilattice
    satisfying Commutativity (`A ⊔ B = B ⊔ A`), Associativity (`(A ⊔ B) ⊔ C = A ⊔ (B ⊔ C)`), and
    Idempotence (`A ⊔ A = A`). -/
theorem merkle_dag_semilattice_laws (A B C : Nat → Prop) :
    (∀ d, dagJoinSet A B d ↔ dagJoinSet B A d) ∧
    (∀ d, dagJoinSet (dagJoinSet A B) C d ↔ dagJoinSet A (dagJoinSet B C) d) ∧
    (∀ d, dagJoinSet A A d ↔ A d) := by
  refine ⟨?_, ?_, ?_⟩
  · intro d
    unfold dagJoinSet
    constructor
    · intro h
      cases h with
      | inl ha => exact Or.inr ha
      | inr hb => exact Or.inl hb
    · intro h
      cases h with
      | inl hb => exact Or.inr hb
      | inr ha => exact Or.inl ha
  · intro d
    unfold dagJoinSet
    constructor
    · intro h
      cases h with
      | inl hab =>
        cases hab with
        | inl ha => exact Or.inl ha
        | inr hb => exact Or.inr (Or.inl hb)
      | inr hc => exact Or.inr (Or.inr hc)
    · intro h
      cases h with
      | inl ha => exact Or.inl (Or.inl ha)
      | inr hbc =>
        cases hbc with
        | inl hb => exact Or.inl (Or.inr hb)
        | inr hc => exact Or.inr hc
  · intro d
    unfold dagJoinSet
    constructor
    · intro h
      cases h with
      | inl ha => exact ha
      | inr ha => exact ha
    · intro ha
      exact Or.inl ha

/-- Theorem 13 (Outward-Rounded Interval Containment & Interior Margin):
    For any real step value `x_exact` satisfying interior bounds `δ_ulp ≤ x_exact` and
    `x_exact + δ_ulp ≤ x_max` with rounding radius `0 ≤ δ_ulp`, the outward-rounded interval
    `[x_exact - δ_ulp, x_exact + δ_ulp]` lies inside `[0, x_max]` (`0 ≤ x_exact - δ_ulp`
    and `x_exact + δ_ulp ≤ x_max`). -/
theorem patankar_interval_rounding_in_box
    (x_exact x_max delta_ulp : ℝ)
    (h_delta : 0 ≤ delta_ulp)
    (h_lo_margin : delta_ulp ≤ x_exact)
    (h_hi_margin : x_exact + delta_ulp ≤ x_max) :
    0 ≤ x_exact - delta_ulp ∧
    x_exact - delta_ulp ≤ x_exact + delta_ulp ∧
    x_exact + delta_ulp ≤ x_max := by
  refine ⟨by linarith, by linarith, by linarith⟩

/-- Record structures for definitional projection lemma (`projection_independent_of_secret`). -/
structure PublicLedgerState where
  pubkeyDigest : Nat
  headDigest   : Nat
  deriving DecidableEq, Repr

structure SignerPrincipalState where
  secretSeed   : Nat
  pubkeyDigest : Nat
  deriving DecidableEq, Repr

/-- Projection function that depends only on `PublicLedgerState`. -/
def applyWorkerProjection (f : PublicLedgerState → Nat) (pub : PublicLedgerState) (_sec : SignerPrincipalState) : Nat :=
  f pub

/-- Theorem 14 (Definitional Projection Lemma — `projection_independent_of_secret`):
    Definitional lemma stating that `applyWorkerProjection f pub` ignores its `_sec` argument.
    Note: This is a definitional projection lemma, not a formal proof of OS-level process isolation;
    process isolation of the Ed25519 signing seed is enforced at runtime by `IsolatedSignerSubprocess`
    (`subprocess.Popen`) and verified by regression tests (`test_32`, `test_41`). -/
theorem projection_independent_of_secret
    (f : PublicLedgerState → Nat)
    (pub : PublicLedgerState)
    (s1 s2 : SignerPrincipalState) :
    applyWorkerProjection f pub s1 = applyWorkerProjection f pub s2 := by
  rfl

/-- Theorem 15 (Two-Step Piecewise Dissipative Duhamel Recurrence vs. Single-Rate Growth):
    For a two-step recurrence `e1 = α * e0 + d1` and `e2 = α * e1 + d2` where `0 ≤ α ≤ G`
    and `0 ≤ e0, d1, d2`, the two-step bound `α * (α * e0 + d1) + d2` is bounded above by
    `G * (G * e0 + d1) + d2`, and is strictly smaller (`α * (α * e0 + d1) + d2 < G * (G * e0 + d1) + d2`)
    whenever `α < G` and `0 < d1`. -/
theorem duhamel_piecewise_contraction_bound
    (alpha G e0 d1 d2 : ℝ)
    (h_alpha : 0 ≤ alpha) (h_le : alpha ≤ G)
    (he0 : 0 ≤ e0) (hd1 : 0 ≤ d1) (hd2 : 0 ≤ d2) :
    alpha * (alpha * e0 + d1) + d2 ≤ G * (G * e0 + d1) + d2 ∧
    (alpha < G → 0 < d1 → alpha * (alpha * e0 + d1) + d2 < G * (G * e0 + d1) + d2) := by
  have h_G : 0 ≤ G := by linarith
  have h_diff : 0 ≤ G - alpha := by linarith
  have h_ae0_le_Ge0 : alpha * e0 ≤ G * e0 := by
    have h1 : 0 ≤ (G - alpha) * e0 := mul_nonneg h_diff he0
    linarith
  have h_ae0_nonneg : 0 ≤ alpha * e0 := mul_nonneg h_alpha he0
  have h_inner_nonneg : 0 ≤ alpha * e0 + d1 := by linarith
  have h_step1 : alpha * (alpha * e0 + d1) ≤ G * (alpha * e0 + d1) := by
    have h3 : 0 ≤ (G - alpha) * (alpha * e0 + d1) := mul_nonneg h_diff h_inner_nonneg
    linarith
  have h_step2 : G * (alpha * e0 + d1) ≤ G * (G * e0 + d1) := by
    have h_inner_diff : 0 ≤ (G * e0 + d1) - (alpha * e0 + d1) := by linarith
    have h4 : 0 ≤ G * ((G * e0 + d1) - (alpha * e0 + d1)) := mul_nonneg h_G h_inner_diff
    linarith
  constructor
  · linarith
  · intro h_strict hd1_pos
    have h_strict_diff : 0 < G - alpha := by linarith
    have h_inner_pos : 0 < alpha * e0 + d1 := by linarith
    have h_step1_strict : 0 < (G - alpha) * (alpha * e0 + d1) := mul_pos h_strict_diff h_inner_pos
    linarith

/-- Theorem 16 (Unique Reachability of `SealedActive` from `Uninit`):
    A finite trace `evs : List LifecycleEvent` starting at `LifecycleState.Uninit` terminates in
    `LifecycleState.SealedActive` if and only if `evs = [LifecycleEvent.BeginInit, LifecycleEvent.SealSuccess]`. -/
theorem sealed_active_unique_trace_from_uninit (evs : List LifecycleEvent) :
    runTrace LifecycleState.Uninit evs = LifecycleState.SealedActive ↔
    evs = [LifecycleEvent.BeginInit, LifecycleEvent.SealSuccess] := by
  constructor
  · intro h
    cases evs with
    | nil => cases h
    | cons e1 rest1 =>
      cases e1 with
      | SealSuccess =>
        exfalso
        exact sink_trace_ne_sealed rest1 LifecycleState.AbortedPoisoned (Or.inl rfl) h
      | OOMAbort =>
        exfalso
        exact sink_trace_ne_sealed rest1 LifecycleState.AbortedPoisoned (Or.inl rfl) h
      | NormalClose =>
        exfalso
        exact sink_trace_ne_sealed rest1 LifecycleState.AbortedPoisoned (Or.inl rfl) h
      | ZeroAndFree =>
        exfalso
        exact sink_trace_ne_sealed rest1 LifecycleState.AbortedPoisoned (Or.inl rfl) h
      | BeginInit =>
        cases rest1 with
        | nil => cases h
        | cons e2 rest2 =>
          cases e2 with
          | BeginInit =>
            exfalso
            exact sink_trace_ne_sealed rest2 LifecycleState.AbortedPoisoned (Or.inl rfl) h
          | OOMAbort =>
            exfalso
            exact sink_trace_ne_sealed rest2 LifecycleState.AbortedPoisoned (Or.inl rfl) h
          | NormalClose =>
            exfalso
            exact sink_trace_ne_sealed rest2 LifecycleState.AbortedPoisoned (Or.inl rfl) h
          | ZeroAndFree =>
            exfalso
            exact sink_trace_ne_sealed rest2 LifecycleState.AbortedPoisoned (Or.inl rfl) h
          | SealSuccess =>
            cases rest2 with
            | nil => rfl
            | cons e3 rest3 =>
              exfalso
              cases e3 with
              | BeginInit =>
                exact sink_trace_ne_sealed rest3 LifecycleState.AbortedPoisoned (Or.inl rfl) h
              | SealSuccess =>
                exact sink_trace_ne_sealed rest3 LifecycleState.AbortedPoisoned (Or.inl rfl) h
              | OOMAbort =>
                exact sink_trace_ne_sealed rest3 LifecycleState.AbortedPoisoned (Or.inl rfl) h
              | ZeroAndFree =>
                exact sink_trace_ne_sealed rest3 LifecycleState.AbortedPoisoned (Or.inl rfl) h
              | NormalClose =>
                cases rest3 with
                | nil => cases h
                | cons e4 rest4 =>
                  exact sink_trace_ne_sealed rest4
                    (stepLifecycle LifecycleState.ShutdownClean e4)
                    (shutdown_step_in_sink e4) h
  · intro h_evs
    rw [h_evs]
    rfl

#print axioms oom_from_partial_init_is_poisoned
#print axioms no_deref_after_partial_oom_abort
#print axioms no_shutdown_uaf_on_poisoned_state
#print axioms stale_epoch_read_rejected
#print axioms typestate_and_epoch_security_certificate
#print axioms patankar_euler_step_in_box
#print axioms psi_decay_floor_bound
#print axioms merkle_dag_merge_commutative
#print axioms patankar_strict_positivity_floor
#print axioms perturbation_budget_scaling
#print axioms fence_seq_strict_monotonicity
#print axioms merkle_dag_semilattice_laws
#print axioms patankar_interval_rounding_in_box
#print axioms projection_independent_of_secret
#print axioms duhamel_piecewise_contraction_bound
#print axioms sealed_active_unique_trace_from_uninit

end SharkProtocol
