package aescryptography

type IAESCryptography interface {
	GenerateKey() ([]byte, error)

	BuildAAD(topic, policy, version string) []byte

	Encrypt(key, plaintext, aad []byte) (iv, ciphertext []byte, err error)

	Decrypt(key, iv, ciphertext, aad []byte) ([]byte, error)
}
