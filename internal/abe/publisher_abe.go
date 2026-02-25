package abe

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/abe/cpabe/tkn20"
)

type PublisherABE struct {
}

// EncryptKey encrypts session key under some policy & returns ciphertext bytes
func (strct *PublisherABE) EncryptKey(publicKeyBytes []byte, policy string, sessionKey []byte) ([]byte, error) {

	var publicKey tkn20.PublicKey
	var policyTKN tkn20.Policy

	if err := publicKey.UnmarshalBinary(publicKeyBytes); err != nil {
		return nil, fmt.Errorf("abe: failed to load public key: %w", err)
	}

	if err := policyTKN.FromString(policy); err != nil {
		return nil, fmt.Errorf("abe: invalid policy %q: %w", policy, err)
	}

	// Encrypt session key under policy using the public key
	cipherText, err := publicKey.Encrypt(rand.Reader, policyTKN, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("abe: encrypt failed: %w", err)
	}

	return cipherText, nil
}
