package unit

import (
	"bytes"
	aescryptography "securemqtt/internal/aes"
	"testing"
)

var (
	topic   = "topicX"
	policy  = "role:admin AND dept:it"
	version = "v1"
)

func TestAES_RoundTrip(t *testing.T) {
	crypto := &aescryptography.AESCryptography{}

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	if len(key) != aescryptography.KeySize {
		t.Fatalf("unexpected key size: got %d want %d", len(key), aescryptography.KeySize)
	}

	aad := crypto.BuildAAD(topic, policy, version)

	plaintext := []byte("hello world")

	nonce, ct, err := crypto.Encrypt(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	if len(nonce) == 0 {
		t.Fatalf("Encrypt() returned empty nonce")
	}
	if len(ct) == 0 {
		t.Fatalf("Encrypt() returned empty ciphertext")
	}

	got, err := crypto.Decrypt(key, nonce, ct, aad)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestAES_TamperCiphertext_Fails(t *testing.T) {
	crypto := &aescryptography.AESCryptography{}

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	aad := crypto.BuildAAD(topic, policy, version)
	plaintext := []byte("secret message")

	nonce, ct, err := crypto.Encrypt(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Flip 1 byte in ciphertext (includes  tag at end).
	ct2 := make([]byte, len(ct))
	copy(ct2, ct)
	ct2[len(ct2)/2] ^= 0x01

	if _, err := crypto.Decrypt(key, nonce, ct2, aad); err == nil {
		t.Fatalf("expected decryption failure after ciphertext tamper; got nil error")
	}
}

func TestAES_TamperIV_Fails(t *testing.T) {
	crypto := &aescryptography.AESCryptography{}

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	aad := crypto.BuildAAD(topic, policy, version)
	plaintext := []byte("secret message")

	iv, ct, err := crypto.Encrypt(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Flip 1 byte in nonce.
	iv2 := make([]byte, len(iv))
	copy(iv2, iv)
	iv2[0] ^= 0x01

	if _, err := crypto.Decrypt(key, iv2, ct, aad); err == nil {
		t.Fatalf("expected decryption failure after nonce tamper; got nil error")
	}
}

func TestAES_TamperAAD_Fails(t *testing.T) {
	crypto := &aescryptography.AESCryptography{}

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	// Encrypt under one context...
	aad := crypto.BuildAAD(topic, policy, version)
	plaintext := []byte("secret message")

	iv, ct, err := crypto.Encrypt(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Attempt to decrypt under a different topic
	badAAD := crypto.BuildAAD("topicY", policy, version)

	if _, err := crypto.Decrypt(key, iv, ct, badAAD); err == nil {
		t.Fatalf("expected decryption failure after AAD change; got nil error")
	}
}
