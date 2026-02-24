package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// Byte number used by symmetric key
// 16 bytes - 128-bit key (AES-128).
const KeySize = 16

// To be replaced by CP-ABE
var HardcodedKey, _ = hex.DecodeString("e0b93100018d417c7a25b447c2633059")

// Generate fresh random symmetric key of KeySize bytes.
func GenerateKey() ([]byte, error) {

	// Allocate a byte slice of length KeySize.
	secretKey := make([]byte, KeySize)

	// Fill it with cryptographically secure random bytes.
	// Package rand implements a cryptographically secure random number generator
	if _, err := io.ReadFull(rand.Reader, secretKey); err != nil {
		return nil, nil
	}
	return secretKey, nil
}

// Construct the Additional Authenticated Data (AAD) for AES
// Bind ciphertext to its “context”:
// 1. Topic -> Prevents copying ciphertext to another topic and still decrypting
// 2. Policy -> Prevents swapping policy strings while keeping ciphertext
// 3. Version -> Prevents mixing versions
func BuildAAD(topic, policy, version string) []byte {
	// Concatenate with '|' delimiter so fields are distinguishable.
	return []byte(fmt.Sprintf("%s|%s|%s", version, topic, policy))
}

// Encrypt plaintext with AES
// Provide the:
// 1. Secret key
// 2. Plaintext
// 3. AAD
// Function will provide us with:
// 1. IV -> Unique per encryption under same key
// 2. Ciphertext -> Encrypted bytes + authentication tag appended
func Encrypt(key, plaintext, aad []byte) (iv, ciphertext []byte, err error) {

	// Create AES block cipher from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: cipher init failed: %w", err)
	}

	// Put cipher in GCM mode, providing:
	// 1. Confidentiality
	// 2. Integrity
	// 3. Authenticity
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: GCM init failed: %w", err)
	}

	// Create a slice for IV & fill it with secure random bytes
	// New one for every encryption
	iv = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, fmt.Errorf("crypto: nonce generation failed: %w", err)
	}

	// Encrypt & append authentication tag
	// Tag is computer over ciphertext, AAD & IV
	ciphertext = gcm.Seal(nil, iv, plaintext, aad)
	return iv, ciphertext, nil
}

// Decrypt decrypts AES ciphertext by receiving:
// 1. Secret key
// 2. IV - same one used for encryption
// 3. AAD
func Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {

	// Build block cipher from key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: cipher init failed: %w", err)
	}

	// Put in GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: GCM init failed: %w", err)
	}

	// Verify authentication tag & decrypt in one step
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("crypto: decryption failed: %w", err)
	}

	return plaintext, nil
}
