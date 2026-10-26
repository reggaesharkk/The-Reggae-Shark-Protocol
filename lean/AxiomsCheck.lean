import BoundaryVerification
import ExistenceVerification
import TypestateLifecycle

open SharkProtocol

/-!
# Unified 42-Theorem Axiom Audit (`lean/AxiomsCheck.lean`)
Prints the exact axiom dependencies for all 42 theorems across:
1. `lean/BoundaryVerification.lean` (9 theorems)
2. `lean/ExistenceVerification.lean` (17 theorems)
3. `lean/TypestateLifecycle.lean` (16 theorems)

Verified in CI via `lake env lean lean/AxiomsCheck.lean | python3 tools/check_lean_axioms.py`
to ensure every theorem depends only on a subset of `{propext, Classical.choice, Quot.sound}`
with zero `sorryAx` and zero custom axioms.
-/

-- Module 1: BoundaryVerification (9 theorems)
#print axioms dgamma_dt_nonneg_at_boundary
#print axioms dgamma_dt_pos_at_boundary
#print axioms dgamma_dt_neg_at_ceiling
#print axioms dHobs_dt_nonneg_at_boundary
#print axioms dHobs_dt_neg_at_ceiling
#print axioms dIdot_dt_pos_at_boundary
#print axioms dHobs_dt_le_M_H
#print axioms dIdot_dt_nonpos_at_ceiling
#print axioms compact_box_nagumo_certificate

-- Module 2: ExistenceVerification (17 theorems)
#print axioms R_self_sq_nonneg
#print axioms dgamma_dt_4D_nonneg_at_boundary
#print axioms dgamma_dt_4D_ge_neg_decay
#print axioms dgamma_dt_4D_neg_at_ceiling
#print axioms dHobs_dt_4D_nonneg_at_boundary
#print axioms dHobs_dt_4D_neg_at_ceiling
#print axioms P_eff_pos_on_box
#print axioms dIdot_dt_4D_pos_at_boundary
#print axioms dIdot_dt_4D_nonneg_at_boundary_zero_drive
#print axioms dHobs_dt_4D_le_M_H
#print axioms dHobs_dt_4D_ge_neg_M_H
#print axioms dIdot_dt_4D_ge_linear_floor
#print axioms P_eff_le_P_eff_max
#print axioms dIdot_dt_4D_nonpos_at_ceiling
#print axioms dPsi_dt_4D_nonneg_at_boundary
#print axioms dPsi_dt_4D_neg_at_ceiling
#print axioms existence_box_8face_nagumo_certificate

-- Module 3: TypestateLifecycle (16 theorems)
#print axioms SharkProtocol.oom_from_partial_init_is_poisoned
#print axioms SharkProtocol.no_deref_after_partial_oom_abort
#print axioms SharkProtocol.no_shutdown_uaf_on_poisoned_state
#print axioms SharkProtocol.stale_epoch_read_rejected
#print axioms SharkProtocol.typestate_and_epoch_security_certificate
#print axioms SharkProtocol.patankar_euler_step_in_box
#print axioms SharkProtocol.psi_decay_floor_bound
#print axioms SharkProtocol.merkle_dag_merge_commutative
#print axioms SharkProtocol.patankar_strict_positivity_floor
#print axioms SharkProtocol.perturbation_budget_scaling
#print axioms SharkProtocol.fence_seq_strict_monotonicity
#print axioms SharkProtocol.merkle_dag_semilattice_laws
#print axioms SharkProtocol.patankar_interval_rounding_in_box
#print axioms SharkProtocol.projection_independent_of_secret
#print axioms SharkProtocol.duhamel_piecewise_contraction_bound
#print axioms SharkProtocol.sealed_active_unique_trace_from_uninit
