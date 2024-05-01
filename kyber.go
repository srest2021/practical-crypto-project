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

//encapsulation: "github.com/linckode/circl/kem/kyber/kyber768"

// const X25519Label = "age-encryption.org/v1/X25519" //?????
const KyberLabel = "kyber" //change later once I look into it more

type KyberRecipient struct {
	theirPublicKey []byte
}

// newKyberRecipientFromPoint returns a new KyberRecipient.
func newKyberRecipient(publicKey []byte) (*KyberRecipient, error) {
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
	r, err := newKyberRecipient(k)
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

func PackIdentity(publicKey kyber768.PublicKey, privateKey kyber768.PrivateKey) (*KyberIdentity, error) {
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

// GenerateKyberIdentity randomly generates a new KyberIdentity.
func GenerateKyberIdentity() (*KyberIdentity, error) {
	publicKey, privateKey, err := kyber768.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return PackIdentity(*publicKey, *privateKey)
}

// NOTE: may actually want all keys to be seeded? original x25519 stuff is all seeded... up to us probably
// same idea as newX25519IdentityFromScalar because we are taking in k which is the given private key
// this is verses the GenerateKyberIdentity. in that function above we aren't given a secret key
// so we just make the identity info based off of rand.Reader, which is just like how it's done in
// GenerateX25519Identity
func GenerateSeededKyberIdentity(k []byte) (*KyberIdentity, error) {
	publicKey, privateKey := kyber768.NewKeyFromSeed(k)
	return PackIdentity(*publicKey, *privateKey)
}

// ParseKyberIdentity returns a new KyberIdentity from a Bech32 private key
// encoding with the "AGE-SECRET-KEY-1" prefix.
func ParseKyberIdentity(s string) (*KyberIdentity, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	if t != "AGE-K-SECRET-KEY-" {
		return nil, fmt.Errorf("malformed secret key: unknown type %q", t)
	}
	r, err := GenerateSeededKyberIdentity(k)
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
