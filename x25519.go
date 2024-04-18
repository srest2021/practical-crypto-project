// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"filippo.io/age/internal/bech32"
	"golang.org/x/crypto/curve25519"
)

const x25519Label = "age-encryption.org/v1/X25519"

// X25519Recipient is the standard age public key. Messages encrypted to this
// recipient can be decrypted with the corresponding X25519Identity.
//
// This recipient is anonymous, in the sense that an attacker can't tell from
// the message alone if it is encrypted to a certain recipient.
type X25519Recipient struct {
	theirPublicKey []byte
}

var _ Recipient = &X25519Recipient{}

// newX25519RecipientFromPoint returns a new X25519Recipient from a raw Curve25519 point.
// kyber x25519: instead of curve point size, maybe that + size of kyber key
func newX25519RecipientFromPoint(publicKey []byte) (*X25519Recipient, error) {
	if len(publicKey) != curve25519.PointSize {
		return nil, errors.New("invalid X25519 public key")
	}
	r := &X25519Recipient{
		theirPublicKey: make([]byte, curve25519.PointSize),
	}
	copy(r.theirPublicKey, publicKey)
	return r, nil
}

// ParseX25519Recipient returns a new X25519Recipient from a Bech32 public key
// encoding with the "age1" prefix.
func ParseX25519Recipient(s string) (*X25519Recipient, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	if t != "age" {
		return nil, fmt.Errorf("malformed recipient %q: invalid type %q", s, t)
	}
	r, err := newX25519RecipientFromPoint(k)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	return r, nil
}

// String returns the Bech32 public key encoding of r.
func (r *X25519Recipient) String() string {
	s, _ := bech32.Encode("age", r.theirPublicKey)
	return s
}

// X25519Identity is the standard age private key, which can decrypt messages
// encrypted to the corresponding X25519Recipient.
type X25519Identity struct {
	secretKey, ourPublicKey []byte
}

var _ Identity = &X25519Identity{}

// newX25519IdentityFromScalar returns a new X25519Identity from a raw Curve25519 scalar.
func newX25519IdentityFromScalar(secretKey []byte) (*X25519Identity, error) {
	if len(secretKey) != curve25519.ScalarSize {
		return nil, errors.New("invalid X25519 secret key")
	}
	i := &X25519Identity{
		secretKey: make([]byte, curve25519.ScalarSize),
	}
	copy(i.secretKey, secretKey)
	i.ourPublicKey, _ = curve25519.X25519(i.secretKey, curve25519.Basepoint)
	return i, nil
}

// GenerateX25519Identity randomly generates a new X25519Identity.
func GenerateX25519Identity() (*X25519Identity, error) {
	secretKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(secretKey); err != nil {
		return nil, fmt.Errorf("internal error: %v", err)
	}
	return newX25519IdentityFromScalar(secretKey)
}

// ParseX25519Identity returns a new X25519Identity from a Bech32 private key
// encoding with the "AGE-SECRET-KEY-1" prefix.
func ParseX25519Identity(s string) (*X25519Identity, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	if t != "AGE-SECRET-KEY-" {
		return nil, fmt.Errorf("malformed secret key: unknown type %q", t)
	}
	r, err := newX25519IdentityFromScalar(k)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	return r, nil
}

// Recipient returns the public X25519Recipient value corresponding to i.
func (i *X25519Identity) Recipient() *X25519Recipient {
	r := &X25519Recipient{}
	r.theirPublicKey = i.ourPublicKey
	return r
}

// String returns the Bech32 private key encoding of i.
func (i *X25519Identity) String() string {
	s, _ := bech32.Encode("AGE-SECRET-KEY-", i.secretKey)
	return strings.ToUpper(s)
}
