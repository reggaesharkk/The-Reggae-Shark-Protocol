import Lake
open Lake DSL

package «sharkProtocolVerification» where
  leanOptions := #[
    ⟨`pp.unicode.fun, true⟩,
    ⟨`autoImplicit, false⟩
  ]

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "10156080d0e7997b71f3ef86bd6f0211b42ab90d"

@[default_target]
lean_lib «ExistenceVerification» where
  srcDir := "lean"

@[default_target]
lean_lib «BoundaryVerification» where
  srcDir := "lean"

@[default_target]
lean_lib «TypestateLifecycle» where
  srcDir := "lean"

@[default_target]
lean_lib «AxiomsCheck» where
  srcDir := "lean"
