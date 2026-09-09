module github.com/jwx-go/benchmarks/suites/golang-jwt-pqc

go 1.27.0

// The published ML-DSA submodule requires its own parent module at v0.0.0, a
// version that was never tagged, because the upstream repository builds it
// through a local replace directive. Pinning the parent to a real release is
// what makes that submodule resolvable from outside the upstream repository.
replace github.com/salrashid123/golang-jwt-pqc => github.com/salrashid123/golang-jwt-pqc v0.0.60

require (
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/salrashid123/golang-jwt-pqc v0.0.0
	github.com/salrashid123/golang-jwt-pqc/mldsa v0.0.60
)
