package abe

type ISubscriberABE interface {
	// Decrypts ciphertext using the subscriber's private key
	// Takes as input: ciphertext
	// Outputs:
	// 1. Plaintext session key
	DecryptKey(privateKeyBytes []byte, ciphertext []byte) ([]byte, error)
}
