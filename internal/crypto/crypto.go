package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

const KeySize = 16

// HardcodedKey is a placeholder shared key for Step 2.
// Replaced by CP-ABE-distributed session keys in Step 3.
var HardcodedKey, _ = hex.DecodeString("e0b93100018d417c7a25b447c2633059")

func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("crypto: key generation failed: %w", err)
	}
	return key, nil
}

// BuildAAD constructs the additional authenticated data from the MQTT topic,
// policy string, and envelope version. This binds the ciphertext to its
// context — decryption fails if any of these fields are tampered with or
// if the ciphertext is replayed on a different topic.
func BuildAAD(topic, policy, version string) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s", version, topic, policy))
}

// Encrypt encrypts plaintext with AES-GCM.
// Returns the nonce and ciphertext (ciphertext already includes the GCM tag appended).
func Encrypt(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: cipher init failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: GCM init failed: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("crypto: nonce generation failed: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

// Decrypt decrypts AES-GCM ciphertext
func Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: cipher init failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: GCM init failed: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("crypto: decryption failed: %w", err)
	}

	return plaintext, nil
}
