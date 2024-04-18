package age

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"filippo.io/age/internal/bech32"
	"filippo.io/age/internal/format"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/Universal-Health-Chain/uhc-cloudflare-circl/pke/kyber/kyber768"
)

func (r *KyberRecipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	privateKey, publicKey, err := kyber768.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ourPublicKey := make([]byte, kyber768.PublicKeySize)
	publicKey.Pack(ourPublicKey)

	l := &Stanza{
		Type: "Kyber",
		Args: []string{format.EncodeToString(ourPublicKey)},
	}

	//figuring out what to do with this stuff
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(publicKey, wrappingKey); err != nil {
		return nil, err
	}

	wrappedKey, err := aeadEncrypt(wrappingKey, fileKey)
	if err != nil {
		return nil, err
	}
	l.Body = wrappedKey

	return []*Stanza{l}, nil
}

// String returns the Bech32 public key encoding of r.
func (r *KyberRecipient) String() string {
	s, _ := bech32.Encode("age", r.theirPublicKey)
	return s
}

func (i *KyberIdentity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	return multiUnwrap(i.unwrap, stanzas)
}

func (i *KyberIdentity) unwrap(block *Stanza) ([]byte, error) {
	if block.Type != "Kyber" {
		return nil, ErrIncorrectIdentity
	}
	if len(block.Args) != 1 {
		return nil, errors.New("invalid Kyber recipient block")
	}
	publicKey, err := format.DecodeString(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse Kyber recipient: %v", err)
	}
	if len(publicKey) != curve25519.PointSize {
		return nil, errors.New("invalid Kyber recipient block")
	}

	sharedSecret, err := curve25519.X25519(i.secretKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid Kyber recipient: %v", err)
	}

	salt := make([]byte, 0, len(publicKey)+len(i.ourPublicKey))
	salt = append(salt, publicKey...)
	salt = append(salt, i.ourPublicKey...)
	h := hkdf.New(sha256.New, sharedSecret, salt, []byte(KyberLabel))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	fileKey, err := aeadDecrypt(wrappingKey, fileKeySize, block.Body)
	if err == errIncorrectCiphertextSize {
		return nil, errors.New("invalid Kyber recipient block: incorrect file key size")
	} else if err != nil {
		return nil, ErrIncorrectIdentity
	}
	return fileKey, nil
}
