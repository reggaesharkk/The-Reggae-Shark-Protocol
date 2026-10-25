import Mathlib.Tactic.Linarith
import Mathlib.Data.Real.Basic

/-!
# Formal Request-Lifecycle Typestate, Worker-Epoch Isolation, Discrete Box Step,
# Capacitive Decay Floor, and Merkle-DAG Join Commutativity (`TypestateLifecycle.lean`)

Author: Prince Upadhyay (ORCID: 0009-0002-1170-4487)
Version: 1.1.2 (Canonical DOI: 10.5281/zenodo.23624605)
License: MIT License

## Scope & Claim Boundary (`does_not_imply`)
This module machine-checks eight formal properties of the Shark Protocol's mathematical models:
1. Five theorems (`oom_from_partial_init_is_poisoned`, `no_deref_after_partial_oom_abort`,
   `no_shutdown_uaf_on_poisoned_state`, `stale_epoch_read_rejected`, and
   `typestate_and_epoch_security_certificate`) formalizing an application-level request-lifecycle
   typestate automaton and worker-epoch guard that rule out partial-initialization payload
   dereferencing and cross-epoch worker-slot reads within the modelled state machine.
2. Three red-team bridge theorems addressing continuous-to-discrete step invariance
   (`patankar_euler_step_in_box`), slow self-modeling capacitive decay lower bounds
   (`psi_decay_floor_bound`), and distributed Merkle-DAG parent-pair join commutativity
   (`merkle_dag_merge_commutative`).

**What is NOT claimed:** These theorems prove properties of the formal state-transition and
algebraic models defined in this file. They do not verify a native C/PHP interpreter runtime,
OS kernel ring-0 memory allocator, or hardware ARM64/x86 cache-coherency protocol.
-/

namespace SharkProtocol

/-- Six-state request lifecycle automaton. -/
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

/-- Deterministic state transition function δ : LifecycleState → LifecycleEvent → LifecycleState. -/
def stepLifecycle (s : LifecycleState) (ev : LifecycleEvent) : LifecycleState :=
  match s, ev with
  | LifecycleState.Uninit,          LifecycleEvent.BeginInit   => LifecycleState.PartialInit
  | LifecycleState.PartialInit,     LifecycleEvent.SealSuccess => LifecycleState.SealedActive
  | LifecycleState.PartialInit,     LifecycleEvent.OOMAbort    => LifecycleState.AbortedPoisoned
  | LifecycleState.SealedActive,    LifecycleEvent.OOMAbort    => LifecycleState.AbortedPoisoned
  | LifecycleState.SealedActive,    LifecycleEvent.NormalClose => LifecycleState.ShutdownClean
  | LifecycleState.ShutdownClean,   LifecycleEvent.ZeroAndFree => LifecycleState.ZeroedFreed
  | LifecycleState.AbortedPoisoned, LifecycleEvent.ZeroAndFree => LifecycleState.ZeroedFreed
  | _,                              _                          => LifecycleState.AbortedPoisoned

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

/-- Theorem 1: An out-of-memory abort during `PartialInit` transitions strictly to `AbortedPoisoned`. -/
theorem oom_from_partial_init_is_poisoned :
    stepLifecycle LifecycleState.PartialInit LifecycleEvent.OOMAbort = LifecycleState.AbortedPoisoned := by
  rfl

/-- Theorem 2: Payload dereferencing is ruled out after a partial-initialization OOM abort. -/
theorem no_deref_after_partial_oom_abort :
    ¬ canDereferencePayload (stepLifecycle LifecycleState.PartialInit LifecycleEvent.OOMAbort) := by
  intro h
  cases h

/-- Theorem 3: Clean destructor execution is ruled out on a poisoned partial-initialization state. -/
theorem no_shutdown_uaf_on_poisoned_state :
    ¬ canRunCleanDestructor (stepLifecycle LifecycleState.PartialInit LifecycleEvent.OOMAbort) := by
  intro h
  cases h

/-- Theorem 4: Any worker slot from a stale epoch (`slot.slotEpoch ≠ workerEpoch`) cannot be read. -/
theorem stale_epoch_read_rejected (workerEpoch : Nat) (slot : WorkerSlot)
    (h_stale : slot.slotEpoch ≠ workerEpoch) :
    ¬ canAccessWorkerSlot workerEpoch slot := by
  intro h_access
  exact h_stale h_access.1

/-- Theorem 5: Joint typestate and worker-epoch lifecycle certificate. -/
theorem typestate_and_epoch_security_certificate (workerEpoch : Nat) (slot : WorkerSlot)
    (h_stale : slot.slotEpoch ≠ workerEpoch) :
    (stepLifecycle LifecycleState.PartialInit LifecycleEvent.OOMAbort = LifecycleState.AbortedPoisoned) ∧
    (¬ canDereferencePayload (stepLifecycle LifecycleState.PartialInit LifecycleEvent.OOMAbort)) ∧
    (¬ canRunCleanDestructor (stepLifecycle LifecycleState.PartialInit LifecycleEvent.OOMAbort)) ∧
    (¬ canAccessWorkerSlot workerEpoch slot) := by
  refine ⟨oom_from_partial_init_is_poisoned, no_deref_after_partial_oom_abort,
          no_shutdown_uaf_on_poisoned_state, stale_epoch_read_rejected workerEpoch slot h_stale⟩

/-- Theorem 6 (Red-Team Problem 1 — Discrete Patankar-Euler Box Invariance):
    For any state `x ∈ [0, x_max]`, step size `dt > 0`, non-negative production weight `P ≥ 0`,
    and non-negative destruction weight `D ≥ 0`, the unconditionally positive Patankar-Euler
    numerator `num = x + dt * P * x_max` and denominator `den = 1 + dt * (P + D)` satisfy
    `0 ≤ num` and `num ≤ x_max * den`, guaranteeing `0 ≤ num / den ≤ x_max` for all `dt > 0`
    without truncation overshoot across the box faces. -/
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

/-- Theorem 7 (Red-Team Problem 2 — Capacitive Self-Modeling Decay Floor):
    Whenever `κ_meta ≥ 0`, `R_self ≥ 0`, and `Ψ ≤ 1`, the metacognitive velocity
    `dΨ/dt = κ_meta * R_self * (1 - Ψ) - μ_Ψ * Ψ` is bounded below by `-μ_Ψ * Ψ`,
    ruling out instantaneous downward jumps faster than the passive exponential decay rate `μ_Ψ`. -/
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

/-- Theorem 8 (Red-Team Problem 5 — Commutative Merkle-DAG Join-Semilattice):
    Canonical parent-pair ordering is strictly commutative (`canonicalMergePair hA hB = canonicalMergePair hB hA`),
    ensuring that two gateway nodes reconciling divergent branches in opposite arrival orders
    compute the exact same Merkle-DAG merge parent tuple. -/
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

#print axioms typestate_and_epoch_security_certificate
#print axioms patankar_euler_step_in_box
#print axioms psi_decay_floor_bound
#print axioms merkle_dag_merge_commutative

end SharkProtocol
