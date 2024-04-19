package age

type HybridRecipient struct {
	theirXPublicKey, theirKPublicKey []byte
}

type HybridIdentity struct {
	secretXKey, secretKKey, ourXPublicKey, ourKPublicKey []byte
}

func createHybridIdentity(x25519_i *X25519Identity, kyber_i *KyberIdentity) *HybridIdentity {
	i := &HybridIdentity{
		secretXKey:    x25519_i.secretKey,
		secretKKey:    kyber_i.secretKey,
		ourXPublicKey: x25519_i.ourPublicKey,
		ourKPublicKey: kyber_i.ourPublicKey,
	}
	return i
}

func createHybridRecipient(x25519_r *X25519Recipient, kyber_r *KyberRecipient) *HybridRecipient {
	r := &HybridRecipient{
		theirXPublicKey: x25519_r.theirPublicKey,
		theirKPublicKey: kyber_r.theirPublicKey,
	}
	return r
}
