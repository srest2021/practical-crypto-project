package age

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

func (r *HybridRecipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	return []*Stanza{}, nil
}

func (i *HybridIdentity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	return multiUnwrap(i.unwrap, stanzas)
}

func (i *HybridIdentity) unwrap(block *Stanza) ([]byte, error) {
	return nil, nil
}
