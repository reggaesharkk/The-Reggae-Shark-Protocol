import Lake
open Lake DSL

package «shark_protocol» where
  -- Shark Protocol v1.2.0 Formal Verification Package (Lean 4 + Mathlib, 38 Theorems)

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git"

@[default_target]
lean_lib «ExistenceVerification» where
  srcDir := "lean"

lean_lib «BoundaryVerification» where
  srcDir := "lean"

lean_lib «TypestateLifecycle» where
  srcDir := "lean"
