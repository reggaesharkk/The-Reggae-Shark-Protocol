import Lake
open Lake DSL

package «shark_protocol» where
  moreLeanArgs := #["-DautoImplicit=false"]

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.15.0"

@[default_target]
lean_lib «ExistenceVerification» where
  srcDir := "lean"

lean_lib «BoundaryVerification» where
  srcDir := "lean"

lean_lib «TypestateLifecycle» where
  srcDir := "lean"

lean_lib «AxiomsCheck» where
  srcDir := "lean"
