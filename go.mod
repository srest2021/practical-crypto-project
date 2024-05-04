module github.com/srest2021/practical-crypto-project

go 1.21

toolchain go1.21.6

require (
	filippo.io/edwards25519 v1.0.0
	golang.org/x/crypto v0.11.1-0.20230711161743-2e82bdd1719d
	golang.org/x/sys v0.20.0
	golang.org/x/term v0.10.0
)

require github.com/cloudflare/circl v1.3.8

// kyber768
//require github.com/Universal-Health-Chain/uhc-cloudflare-circl v1.0.0
//require github.com/cloudflare/circl/pke/kyber/kyber768 v1.3.8

// Test dependencies.
require (
	c2sp.org/CCTV/age v0.0.0-20221230231406-5ea85644bd03
	github.com/rogpeppe/go-internal v1.8.1
	golang.org/x/tools v0.1.12 // indirect
)

// https://github.com/rogpeppe/go-internal/pull/172
replace github.com/rogpeppe/go-internal => github.com/FiloSottile/go-internal v1.8.2-0.20230806172430-94b0f0dc0b1e
