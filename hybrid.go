package age

import (
	"strings"

	"github.com/srest2021/practical-crypto-project/internal/bech32"
)

type HybridRecipient struct {
	theirXPublicKey, theirKPublicKey []byte
}

type HybridIdentity struct {
	secretXKey, secretKKey, ourXPublicKey, ourKPublicKey []byte
}

func CreateHybridIdentity(x25519_i *X25519Identity, kyber_i *KyberIdentity) *HybridIdentity {
	i := &HybridIdentity{
		secretXKey:    x25519_i.secretKey,
		secretKKey:    kyber_i.secretKey,
		ourXPublicKey: x25519_i.ourPublicKey,
		ourKPublicKey: kyber_i.ourPublicKey,
	}
	return i
}

func CreateHybridRecipient(x25519_r *X25519Recipient, kyber_r *KyberRecipient) *HybridRecipient {
	r := &HybridRecipient{
		theirXPublicKey: x25519_r.theirPublicKey,
		theirKPublicKey: kyber_r.theirPublicKey,
	}
	return r
}

// Recipient returns the public HybridRecipient value corresponding to i.
func (i *HybridIdentity) Recipient() *HybridRecipient {
	r := &HybridRecipient{}
	r.theirXPublicKey = i.ourXPublicKey
	r.theirKPublicKey = i.ourKPublicKey
	return r
}

// String returns the Bech32 private key encoding of i.
func (i *HybridIdentity) String() string {
	x25519_s, _ := bech32.Encode("AGE-X-SECRET-KEY-", i.secretXKey)
	kyber_s, _ := bech32.Encode("AGE-K-SECRET-KEY-", i.secretKKey)
	s := x25519_s + "\n" + kyber_s
	return strings.ToUpper(s)
}

// String returns the Bech32 public key encoding of r.
func (r *HybridRecipient) String() string {
	x25519_s, _ := bech32.Encode("agex", r.theirXPublicKey)
	kyber_s, _ := bech32.Encode("agek", r.theirXPublicKey)
	s := x25519_s + "\n" + kyber_s
	return s
}

func (r *HybridRecipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	return []*Stanza{}, nil
}

func (i *HybridIdentity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	return multiUnwrap(i.unwrap, stanzas)
}

func (i *HybridIdentity) unwrap(block *Stanza) ([]byte, error) {
	return nil, nil
}
