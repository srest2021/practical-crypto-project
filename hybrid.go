package age

type HybridRecipient struct {
	theirXPublicKey, theirKPublicKey []byte
}

type HybridIdentity struct {
	secretXKey, secretKKey, ourXPublicKey, ourKPublicKey []byte
}
