package abe

type IPublisherABE interface {

	// Encrypts session key (symmetric) under a given CP-ABE policy
	// Takes as input:
	// 1. Policy -> Access policy
	// 2. Session Key
	// Outputs: Ciphertext
	EncryptKey(publicKeyBytes []byte, policy string, sessionKey []byte) ([]byte, error)
}
