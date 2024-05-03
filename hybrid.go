package age

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Universal-Health-Chain/uhc-cloudflare-circl/pke/kyber/kyber768"
	"github.com/srest2021/practical-crypto-project/internal/bech32"
	"github.com/srest2021/practical-crypto-project/internal/format"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const hybridLabel = "github.com/srest2021/practical-crypto-project"
const salt = "age-encryption.org/Kyber768+X25519"

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
	kyber_s, _ := bech32.Encode("agek", r.theirKPublicKey)
	s := x25519_s + "\n" + kyber_s
	return s
}

// UnpackHybridRecipient unpacks the recipient's Kyber768 public key.
func (r *HybridRecipient) UnpackKyberPublicKey() kyber768.PublicKey {
	var pubKey kyber768.PublicKey
	pubKey.Unpack(r.theirKPublicKey)
	return pubKey
}

// KyberEncapsulate encapsulates a randomly generated key to the recipient's Kyber768 public key
// and returns the key and peer share.
func KyberEncapsulate(r *HybridRecipient) ([]byte, []byte) {
	// generate random k (not sure if this is right?)
	k := make([]byte, kyber768.PlaintextSize)
	rand.Read(k)

	// generate random seed
	seed := make([]byte, kyber768.EncryptionSeedSize)
	rand.Read(seed)

	// encapsulate k and write Kyber768 peer share to c2
	c2 := make([]byte, kyber768.CiphertextSize)
	unpackedKPublicKey := r.UnpackKyberPublicKey()
	unpackedKPublicKey.EncryptTo(c2, k, seed)
	return c2, k
}

func (r *HybridRecipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	// X25519 ephemeral and peer share
	ephemeral := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(ephemeral); err != nil {
		return nil, err
	}
	c1, err := curve25519.X25519(ephemeral, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	// get shared secret
	sharedSecret, err := curve25519.X25519(ephemeral, r.theirXPublicKey)
	if err != nil {
		return nil, err
	}

	// Kyber768 peer share and shared key
	c2, k := KyberEncapsulate(r)

	l := &Stanza{
		Type: "Hybrid",
		Args: []string{format.EncodeToString(c1), format.EncodeToString(c2)},
	}

	ikm := make([]byte, 0, len(sharedSecret)+len(c1)+len(r.theirXPublicKey)+len(k))
	ikm = append(ikm, sharedSecret...)
	ikm = append(ikm, c1...)
	ikm = append(ikm, r.theirXPublicKey...)
	ikm = append(ikm, k...)
	h := hkdf.New(sha256.New, ikm, []byte(salt), []byte(hybridLabel))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	wrappedKey, err := aeadEncrypt(wrappingKey, fileKey)
	if err != nil {
		return nil, err
	}
	l.Body = wrappedKey

	return []*Stanza{l}, nil
}

// UnpackHybridIdentity unpacks the identity's Kyber768 public and private keys.
func (i *HybridIdentity) UnpackKyberPrivateKey() kyber768.PrivateKey {
	var privKey kyber768.PrivateKey
	privKey.Unpack(i.secretKKey)
	return privKey
}

// KyberDecapsulate decapsulates the peer share to the identity's Kyber768 private key
// and returns the key.
func KyberDecapsulate(i *HybridIdentity, c2 []byte) []byte {
	k := make([]byte, kyber768.PlaintextSize)
	unpackedKPrivateKey := i.UnpackKyberPrivateKey()
	unpackedKPrivateKey.DecryptTo(k, c2)
	return k
}

func (i *HybridIdentity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	return multiUnwrap(i.unwrap, stanzas)
}

func (i *HybridIdentity) unwrap(block *Stanza) ([]byte, error) {
	if block.Type != "Hybrid" {
		return nil, ErrIncorrectIdentity
	}
	if len(block.Args) != 2 {
		return nil, errors.New("invalid Hybrid recipient block")
	}

	// get c1 and c2
	c1, err := format.DecodeString(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse Hybrid recipient's X25519 peer share: %v", err)
	}
	if len(c1) != curve25519.PointSize {
		return nil, errors.New("invalid Hybrid recipient's X25519 peer share")
	}
	c2, err := format.DecodeString(block.Args[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse Hybrid recipient's Kyber768 peer share: %v", err)
	}
	if len(c2) != kyber768.CiphertextSize {
		return nil, errors.New("invalid Hybrid recipient's Kyber768 peer share")
	}

	// recover shared secret
	sharedSecret, err := curve25519.X25519(i.secretXKey, c1)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 recipient: %v", err)
	}

	// recover Kyber768 shared key
	k := KyberDecapsulate(i, c2)

	ikm := make([]byte, 0, len(sharedSecret)+len(c1)+len(i.ourXPublicKey)+len(k))
	ikm = append(ikm, sharedSecret...)
	ikm = append(ikm, c1...)
	ikm = append(ikm, i.ourXPublicKey...)
	ikm = append(ikm, k...)
	h := hkdf.New(sha256.New, ikm, []byte(salt), []byte(hybridLabel))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	fileKey, err := aeadDecrypt(wrappingKey, fileKeySize, block.Body)
	if err == errIncorrectCiphertextSize {
		return nil, errors.New("invalid X25519 recipient block: incorrect file key size")
	} else if err != nil {
		return nil, ErrIncorrectIdentity
	}
	return fileKey, nil
}
