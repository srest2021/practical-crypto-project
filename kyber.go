// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package age

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/srest2021/practical-crypto-project/internal/bech32"
	"golang.org/x/crypto/curve25519"

	"github.com/Universal-Health-Chain/uhc-cloudflare-circl/pke/kyber/kyber768"
)

// const X25519Label = "age-encryption.org/v1/X25519" //?????
const KyberLabel = "kyber" //change later once I look into it more

//X25519
//x25519 things that may need to be changed to Kyber
//curve25519.PointSize: this is the curve the public key is gotten from
//Kyber functiont to use instead: func GenerateKey(rand io.Reader) (*PublicKey, *PrivateKey, error)

// KyberRecipient is the standard age public key. Messages encrypted to this
// recipient can be decrypted with the corresponding KyberIdentity.
//
// This recipient is anonymous, in the sense that an attacker can't tell from
// the message alone if it is encrypted to a certain recipient.
type KyberRecipient struct {
	theirPublicKey []byte
}

var _ Recipient = &KyberRecipient{}

// newKyberRecipientFromPoint returns a new KyberRecipient.
func newKyberRecipientFromPoint(publicKey []byte) (*KyberRecipient, error) {
	if len(publicKey) != kyber768.PublicKeySize {
		return nil, errors.New("invalid KyberRecipient public key")
	}
	r := &KyberRecipient{
		theirPublicKey: make([]byte, kyber768.PublicKeySize),
	}
	copy(r.theirPublicKey, publicKey)
	return r, nil
}

// ParseKyberRecipient returns a new KyberRecipient from a Bech32 public key
// encoding with the "age1" prefix.
func ParseKyberRecipient(s string) (*KyberRecipient, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	if t != "age" {
		return nil, fmt.Errorf("malformed recipient %q: invalid type %q", s, t)
	}
	r, err := newKyberRecipientFromPoint(k)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	return r, nil
}

// String returns the Bech32 public key encoding of r.
func (r *KyberRecipient) String() string {
	s, _ := bech32.Encode("agek", r.theirPublicKey)
	return s
}

// X25519Identity is the standard age private key, which can decrypt messages
// encrypted to the corresponding KyberRecipient.
type KyberIdentity struct {
	secretKey, ourPublicKey []byte
}

var _ Identity = &KyberIdentity{}

// newKyberIdentityFromScalar returns a new X25519Identity from a raw Curve25519 scalar.
func newKyberIdentityFromScalar(secretKey []byte) (*KyberIdentity, error) {
	if len(secretKey) != curve25519.ScalarSize {
		return nil, errors.New("invalid Kyber secret key")
	}
	i := &KyberIdentity{
		secretKey: make([]byte, curve25519.ScalarSize),
	}
	copy(i.secretKey, secretKey)
	i.ourPublicKey, _ = curve25519.X25519(i.secretKey, curve25519.Basepoint)
	return i, nil
}

// GenerateKyberIdentity randomly generates a new KyberIdentity.
func GenerateKyberIdentity() (*KyberIdentity, error) {
	secretKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(secretKey); err != nil {
		return nil, fmt.Errorf("internal error: %v", err)
	}
	return newKyberIdentityFromScalar(secretKey)
}

// ParseKyberIdentity returns a new KyberIdentity from a Bech32 private key
// encoding with the "AGE-SECRET-KEY-1" prefix.
func ParseKyberIdentity(s string) (*KyberIdentity, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	if t != "AGE-SECRET-KEY-" {
		return nil, fmt.Errorf("malformed secret key: unknown type %q", t)
	}
	r, err := newKyberIdentityFromScalar(k)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	return r, nil
}

// Recipient returns the public KyberRecipient value corresponding to i.
func (i *KyberIdentity) Recipient() *KyberRecipient {
	r := &KyberRecipient{}
	r.theirPublicKey = i.ourPublicKey
	return r
}

// String returns the Bech32 private key encoding of i.
func (i *KyberIdentity) String() string {
	s, _ := bech32.Encode("AGE-K-SECRET-KEY-", i.secretKey)
	return strings.ToUpper(s)
}

// dummy functions so that we don't get the "not an identity
// because it doesn't implement wrap/unwrap" error:

func (r *KyberRecipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	return []*Stanza{}, nil
}

func (i *KyberIdentity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	return multiUnwrap(i.unwrap, stanzas)
}

func (i *KyberIdentity) unwrap(block *Stanza) ([]byte, error) {
	return nil, nil
}
