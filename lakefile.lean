import Lake
open Lake DSL

package «shark_protocol» where
  keywords := #["ai", "verification", "ode", "lean4"]

lean_lib «ExistenceVerification» where
  srcDir := "lean"
