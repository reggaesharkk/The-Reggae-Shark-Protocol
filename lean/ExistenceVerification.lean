import Mathlib.Analysis.Calculus.FDeriv.Basic
import Mathlib.Topology.MetricSpace.Basic

open Real

structure State4D where
  gamma : ℝ
  H_obs : ℝ
  I_dot : ℝ
  Psi   : ℝ

def TrappingBox (x : State4D) : Prop :=
  0 ≤ x.gamma ∧ x.gamma ≤ 10.0 ∧
  0 ≤ x.H_obs ∧ x.H_obs ≤ 10.0 ∧
  0 ≤ x.I_dot ∧ x.I_dot ≤ 10.0 ∧
  0 ≤ x.Psi   ∧ x.Psi   ≤ 1.0

theorem box_positivity (x : State4D) (h : TrappingBox x) : x.gamma ≥ 0 := by
  exact h.1
