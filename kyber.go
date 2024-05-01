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

	"github.com/Universal-Health-Chain/uhc-cloudflare-circl/pke/kyber/kyber768"
)

// const X25519Label = "age-encryption.org/v1/X25519" //?????
const KyberLabel = "kyber" //change later once I look into it more

type KyberRecipient struct {
	theirPublicKey []byte
}

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

// X25519Identity is the standard age private key, which can decrypt messages
// encrypted to the corresponding KyberRecipient.
type KyberIdentity struct {
	secretKey, ourPublicKey []byte
}

// GenerateKyberIdentity randomly generates a new KyberIdentity.
func GenerateKyberIdentity() (*KyberIdentity, error) {
	publicKey, privateKey, err := kyber768.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	i := &KyberIdentity{
		secretKey: make([]byte, kyber768.PrivateKeySize),
	}
	//think other code expects bytes so I'm converting privateKey to byte array
	privBuf := make([]byte, kyber768.PrivateKeySize)
	privateKey.Pack(privBuf)
	copy(i.secretKey, privBuf)

	pubBuf := make([]byte, kyber768.PublicKeySize)
	publicKey.Pack(pubBuf)
	copy(i.ourPublicKey, pubBuf)

	return i, nil
}

type Result struct {
	PublicKey PublicKey
	Value     int
}

func encapsulate(pubKyberKey kyber768.PublicKey) Result {
	publicKey := PublicKey
	value := 42
	return Result{PublicKey: publicKey, Value: value}
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
	s, _ := bech32.Encode("HYBRID-SECRET-KEY-", i.secretKey)
	return strings.ToUpper(s)
}
