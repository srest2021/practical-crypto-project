module github.com/srest2021/practical-crypto-project

go 1.21

toolchain go1.21.6

require (
	filippo.io/edwards25519 v1.1.0
	golang.org/x/crypto v0.22.0
	golang.org/x/sys v0.20.0
	golang.org/x/term v0.19.0
)

require github.com/cloudflare/circl v1.3.8

// Test dependencies.
require (
	c2sp.org/CCTV/age v0.0.0-20240306222714-3ec4d716e805
	github.com/rogpeppe/go-internal v1.12.0
	golang.org/x/tools v0.20.0 // indirect
)

// https://github.com/rogpeppe/go-internal/pull/172
replace github.com/rogpeppe/go-internal => github.com/FiloSottile/go-internal v1.8.2-0.20230806172430-94b0f0dc0b1e
