package abe

import (
	"fmt"

	"github.com/cloudflare/circl/abe/cpabe/tkn20"
)

type SubscriberABE struct {
}

// Decrypts ciphertext with the subscriber's private key & returns session key bytes on success
func (strct *SubscriberABE) DecryptKey(privateKeyBytes []byte, ciphertext []byte) ([]byte, error) {

	var privateKey tkn20.AttributeKey
	if err := privateKey.UnmarshalBinary(privateKeyBytes); err != nil {
		return nil, fmt.Errorf("abe: failed to load attribute key: %w", err)
	}

	sessionKey, err := privateKey.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("abe: decryption failed (attributes do not satisfy policy): %w", err)
	}

	return sessionKey, nil
}
