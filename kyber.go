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

	"github.com/Universal-Health-Chain/uhc-cloudflare-circl/pke/kyber/kyber768"
)

//encapsulation: "github.com/linckode/circl/kem/kyber/kyber768"

// const X25519Label = "age-encryption.org/v1/X25519" //?????
const KyberLabel = "kyber" //change later once I look into it more

type KyberRecipient struct {
	theirPublicKey []byte
}

var _ Recipient = &KyberRecipient{}

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
// encoding with the "agek1" prefix.
func ParseKyberRecipient(s string) (*KyberRecipient, error) {
	t, k, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed recipient %q: %v", s, err)
	}
	if t != "agek" {
		return nil, fmt.Errorf("malformed recipient %q: invalid type %q", s, t)
	}
	r, err := newKyberRecipient(k)
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
	secretKey, ourPublicKey, seed []byte
}

var _ Identity = &KyberIdentity{}

func PackIdentity(publicKey kyber768.PublicKey, privateKey kyber768.PrivateKey, seed []byte) (*KyberIdentity, error) {
	i := &KyberIdentity{
		ourPublicKey: make([]byte, kyber768.PublicKeySize),
		secretKey:    make([]byte, kyber768.PrivateKeySize),
		seed:         seed,
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

// // don't know if we'll need to use this
// func UnpackIdentity(i *KyberIdentity) (kyber768.PublicKey, kyber768.PrivateKey) {
// 	var publicKey kyber768.PublicKey
// 	publicKey.Unpack(i.ourPublicKey)

// 	var privateKey kyber768.PrivateKey
// 	privateKey.Unpack(i.secretKey)

// 	return publicKey, privateKey
// }

// // GenerateKyberIdentity randomly generates a new KyberIdentity.
// func GenerateRandomKyberIdentity() (*KyberIdentity, error) {
// 	publicKey, privateKey, err := kyber768.GenerateKey(rand.Reader)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return PackIdentity(*publicKey, *privateKey)
// }

// NOTE: may actually want all keys to be seeded? original x25519 stuff is all seeded... up to us probably
// same idea as newX25519IdentityFromScalar because we are taking in k which is the given private key
// this is verses the GenerateKyberIdentity. in that function above we aren't given a secret key
// so we just make the identity info based off of rand.Reader, which is just like how it's done in
// GenerateX25519Identity
func GenerateKyberIdentityFromSeed(seed []byte) (*KyberIdentity, error) {
	publicKey, privateKey := kyber768.NewKeyFromSeed(seed)
	return PackIdentity(*publicKey, *privateKey, seed)
}

func GenerateSeededKyberIdentity() (*KyberIdentity, error) {
	seed := make([]byte, kyber768.KeySeedSize)
	_, err := rand.Read(seed)
	if err != nil {
		return nil, fmt.Errorf("could not generate seed")
	}
	return GenerateKyberIdentityFromSeed(seed)
}

// ParseKyberIdentity returns a new KyberIdentity from a Bech32 private key
// encoding with the "AGE-K-SECRET-KEY-1" prefix.
func ParseKyberIdentity(s string) (*KyberIdentity, error) {
	fmt.Println("parsing kyber identity: ", s)
	t, seed, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("malformed secret key: %v", err)
	}
	if t != "AGE-K-SECRET-KEY-" {
		return nil, fmt.Errorf("malformed secret key: unknown type %q", t)
	}
	fmt.Println("generating seeded kyber identity from: ", seed)
	r, err := GenerateKyberIdentityFromSeed(seed)
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
	s, _ := bech32.Encode("AGE-K-SECRET-KEY-", i.seed)
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
