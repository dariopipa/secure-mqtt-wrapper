package unit

import (
	"bytes"
	"crypto/rand"
	"testing"

	"securemqtt/internal/abe"

	"github.com/cloudflare/circl/abe/cpabe/tkn20"
)

func setupABE(t *testing.T) (pubKeyBytes []byte, goodAttrKeyBytes []byte, badAttrKeyBytes []byte, policy string, sessionKey []byte) {
	t.Helper()

	// 1) CP-ABE setup (public params + system secret)
	publicKey, systemSecretKey, err := tkn20.Setup(rand.Reader)
	if err != nil {
		t.Fatalf("tkn20.Setup() error: %v", err)
	}

	policy = `(role: operator) and (site: rome)`

	goodAttrs := tkn20.Attributes{}
	goodAttrs.FromMap(map[string]string{
		"role": "operator",
		"site": "rome",
	})

	badAttrs := tkn20.Attributes{}
	badAttrs.FromMap(map[string]string{
		"role": "guest",
		"site": "milan",
	})

	// 3) Generate subscriber attribute keys
	goodKey, err := systemSecretKey.KeyGen(rand.Reader, goodAttrs)
	if err != nil {
		t.Fatalf("systemSecretKey.KeyGen(goodAttrs) error: %v", err)
	}

	badKey, err := systemSecretKey.KeyGen(rand.Reader, badAttrs)
	if err != nil {
		t.Fatalf("systemSecretKey.KeyGen(badAttrs) error: %v", err)
	}

	// 4) Marshal keys to bytes for your adapter API
	pubKeyBytes, err = publicKey.MarshalBinary()
	if err != nil {
		t.Fatalf("publicKey.MarshalBinary() error: %v", err)
	}

	goodAttrKeyBytes, err = goodKey.MarshalBinary()
	if err != nil {
		t.Fatalf("goodKey.MarshalBinary() error: %v", err)
	}

	badAttrKeyBytes, err = badKey.MarshalBinary()
	if err != nil {
		t.Fatalf("badKey.MarshalBinary() error: %v", err)
	}

	// 5) Session key (the thing CP-ABE protects)
	sessionKey = make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		t.Fatalf("rand.Read(sessionKey) error: %v", err)
	}

	return
}

func TestPublisherSubscriberABE_RoundTrip_Succeeds(t *testing.T) {
	pubKeyBytes, goodAttrKeyBytes, _, policy, sessionKey := setupABE(t)

	publisher := &abe.PublisherABE{}
	subscriber := &abe.SubscriberABE{}

	ct, err := publisher.EncryptKey(pubKeyBytes, policy, sessionKey)
	if err != nil {
		t.Fatalf("EncryptKey() error: %v", err)
	}
	if len(ct) == 0 {
		t.Fatalf("EncryptKey() returned empty ciphertext")
	}

	got, err := subscriber.DecryptKey(goodAttrKeyBytes, ct)
	if err != nil {
		t.Fatalf("DecryptKey() error: %v", err)
	}
	if !bytes.Equal(got, sessionKey) {
		t.Fatalf("session key mismatch: got %x want %x", got, sessionKey)
	}
}

func TestSubscriberABE_WrongAttributes_Fails(t *testing.T) {
	pubKeyBytes, _, badAttrKeyBytes, policy, sessionKey := setupABE(t)

	publisher := &abe.PublisherABE{}
	subscriber := &abe.SubscriberABE{}

	ct, err := publisher.EncryptKey(pubKeyBytes, policy, sessionKey)
	if err != nil {
		t.Fatalf("EncryptKey() error: %v", err)
	}

	if _, err := subscriber.DecryptKey(badAttrKeyBytes, ct); err == nil {
		t.Fatalf("expected decryption failure with wrong attributes; got nil error")
	}
}

func TestPublisherABE_InvalidPublicKeyBytes_Fails(t *testing.T) {
	publisher := &abe.PublisherABE{}

	// Not a valid marshaled tkn20.PublicKey
	badPubKey := []byte("not-a-real-public-key")
	policy := `(occupation: doctor) and (country: US)`
	sessionKey := []byte("0123456789abcdef0123456789abcdef")

	if _, err := publisher.EncryptKey(badPubKey, policy, sessionKey); err == nil {
		t.Fatalf("expected failure for invalid public key bytes; got nil error")
	}
}

func TestPublisherABE_InvalidPolicy_Fails(t *testing.T) {
	pubKeyBytes, _, _, _, sessionKey := setupABE(t)

	publisher := &abe.PublisherABE{}

	// Intentionally malformed policy string
	badPolicy := `((occupation: doctor) and`
	if _, err := publisher.EncryptKey(pubKeyBytes, badPolicy, sessionKey); err == nil {
		t.Fatalf("expected failure for invalid policy; got nil error")
	}
}

func TestSubscriberABE_InvalidPrivateKeyBytes_Fails(t *testing.T) {
	pubKeyBytes, _, _, policy, sessionKey := setupABE(t)

	publisher := &abe.PublisherABE{}
	subscriber := &abe.SubscriberABE{}

	ct, err := publisher.EncryptKey(pubKeyBytes, policy, sessionKey)
	if err != nil {
		t.Fatalf("EncryptKey() error: %v", err)
	}

	// Not a valid marshaled tkn20.AttributeKey
	badPrivKey := []byte("not-a-real-attribute-key")

	if _, err := subscriber.DecryptKey(badPrivKey, ct); err == nil {
		t.Fatalf("expected failure for invalid private key bytes; got nil error")
	}
}

func TestSubscriberABE_TamperedCiphertext_Fails(t *testing.T) {
	pubKeyBytes, goodAttrKeyBytes, _, policy, sessionKey := setupABE(t)

	publisher := &abe.PublisherABE{}
	subscriber := &abe.SubscriberABE{}

	ct, err := publisher.EncryptKey(pubKeyBytes, policy, sessionKey)
	if err != nil {
		t.Fatalf("EncryptKey() error: %v", err)
	}

	ct2 := make([]byte, len(ct))
	copy(ct2, ct)
	ct2[len(ct2)/2] ^= 0x01 // flip a bit

	if _, err := subscriber.DecryptKey(goodAttrKeyBytes, ct2); err == nil {
		t.Fatalf("expected failure for tampered ciphertext; got nil error")
	}
}
