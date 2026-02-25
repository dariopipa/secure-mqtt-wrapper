package integration

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"sync"
	"testing"

	"securemqtt/internal"
	"securemqtt/internal/abe"
	aescryptography "securemqtt/internal/aes"
	clientmqtt "securemqtt/internal/clientmqtt"
	secureclient "securemqtt/internal/secureclient"

	"github.com/cloudflare/circl/abe/cpabe/tkn20"
)

const (
	testTopic  = "topicX"
	testPolicy = `(role: operator) and (site: rome)`
)

type memMQTT struct {
	mu        sync.RWMutex
	handlers  map[string][]func(internal.Message)
	onPublish func(topic string, payload []byte) []byte
}

func newMemMQTT() *memMQTT {
	return &memMQTT{
		handlers: make(map[string][]func(internal.Message)),
	}
}

func (m *memMQTT) Publish(topic string, qos byte, retained bool, payload []byte) error {
	m.mu.RLock()
	hs := append([]func(internal.Message){}, m.handlers[topic]...)
	hook := m.onPublish
	m.mu.RUnlock()

	if hook != nil {
		payload = hook(topic, payload)
	}

	msg := internal.Message{Topic: topic, Envelope: payload}
	for _, h := range hs {
		h(msg)
	}
	return nil
}

func (m *memMQTT) Subscribe(topic string, qos byte, handler func(internal.Message)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[topic] = append(m.handlers[topic], handler)
	return nil
}

var _ clientmqtt.IMQTT = (*memMQTT)(nil)

func setupABEKeys(t *testing.T) (pubKeyBytes []byte, goodPrivKeyBytes []byte, badPrivKeyBytes []byte) {
	t.Helper()

	publicKey, systemSecretKey, err := tkn20.Setup(rand.Reader)
	if err != nil {
		t.Fatalf("tkn20.Setup() error: %v", err)
	}

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

	goodKey, err := systemSecretKey.KeyGen(rand.Reader, goodAttrs)
	if err != nil {
		t.Fatalf("KeyGen(goodAttrs) error: %v", err)
	}

	badKey, err := systemSecretKey.KeyGen(rand.Reader, badAttrs)
	if err != nil {
		t.Fatalf("KeyGen(badAttrs) error: %v", err)
	}

	pubKeyBytes, err = publicKey.MarshalBinary()
	if err != nil {
		t.Fatalf("publicKey.MarshalBinary() error: %v", err)
	}

	goodPrivKeyBytes, err = goodKey.MarshalBinary()
	if err != nil {
		t.Fatalf("goodKey.MarshalBinary() error: %v", err)
	}

	badPrivKeyBytes, err = badKey.MarshalBinary()
	if err != nil {
		t.Fatalf("badKey.MarshalBinary() error: %v", err)
	}

	return
}

func TestSecureClient_EndToEnd_AllowsAuthorizedSubscriber(t *testing.T) {
	pubKeyBytes, goodPrivKeyBytes, _ := setupABEKeys(t)

	broker := newMemMQTT()

	// Publisher client (only needs public key)
	publisher := secureclient.NewSecureClient(
		broker,
		&abe.PublisherABE{},
		&abe.SubscriberABE{},
		&aescryptography.AESCryptography{},
		pubKeyBytes,
		nil,
	)

	// Subscriber client (only needs private attribute key)
	subscriber := secureclient.NewSecureClient(
		broker,
		&abe.PublisherABE{},
		&abe.SubscriberABE{},
		&aescryptography.AESCryptography{},
		nil,
		goodPrivKeyBytes,
	)

	plaintext := []byte("hello integration e2e")

	var gotTopic string
	var gotPayload []byte
	called := false

	if err := subscriber.SubscribeSecure(testTopic, 0, func(topic string, pt []byte) {
		called = true
		gotTopic = topic
		gotPayload = append([]byte(nil), pt...)
	}); err != nil {
		t.Fatalf("SubscribeSecure() error: %v", err)
	}

	if err := publisher.PublishSecure(testTopic, 0, false, plaintext, testPolicy); err != nil {
		t.Fatalf("PublishSecure() error: %v", err)
	}

	if !called {
		t.Fatalf("expected subscriber handler to be called")
	}
	if gotTopic != testTopic {
		t.Fatalf("topic mismatch: got %q want %q", gotTopic, testTopic)
	}
	if !bytes.Equal(gotPayload, plaintext) {
		t.Fatalf("payload mismatch: got %q want %q", gotPayload, plaintext)
	}
}

func TestSecureClient_EndToEnd_DeniesUnauthorizedSubscriber(t *testing.T) {
	pubKeyBytes, _, badPrivKeyBytes := setupABEKeys(t)

	broker := newMemMQTT()

	publisher := secureclient.NewSecureClient(
		broker,
		&abe.PublisherABE{},
		&abe.SubscriberABE{},
		&aescryptography.AESCryptography{},
		pubKeyBytes,
		nil,
	)

	unauthorizedSubscriber := secureclient.NewSecureClient(
		broker,
		&abe.PublisherABE{},
		&abe.SubscriberABE{},
		&aescryptography.AESCryptography{},
		nil,
		badPrivKeyBytes,
	)

	called := false
	if err := unauthorizedSubscriber.SubscribeSecure(testTopic, 0, func(topic string, pt []byte) {
		called = true
	}); err != nil {
		t.Fatalf("SubscribeSecure() error: %v", err)
	}

	if err := publisher.PublishSecure(testTopic, 0, false, []byte("secret"), testPolicy); err != nil {
		t.Fatalf("PublishSecure() error: %v", err)
	}

	if called {
		t.Fatalf("handler should not be called for unauthorized subscriber")
	}
}

func TestSecureClient_EndToEnd_TamperedEnvelopePolicy_FailsAESAuth(t *testing.T) {
	pubKeyBytes, goodPrivKeyBytes, _ := setupABEKeys(t)

	broker := newMemMQTT()

	// Tamper the policy inside the JSON envelope *after publish, before delivery*.
	broker.onPublish = func(topic string, payload []byte) []byte {
		var env internal.Envelope
		if err := json.Unmarshal(payload, &env); err != nil {
			return payload
		}
		// AAD will mismatch at subscriber
		env.Policy = `(role: guest) and (site: milan)`
		b, err := json.Marshal(env)
		if err != nil {
			return payload
		}
		return b
	}

	publisher := secureclient.NewSecureClient(
		broker,
		&abe.PublisherABE{},
		&abe.SubscriberABE{},
		&aescryptography.AESCryptography{},
		pubKeyBytes,
		nil,
	)

	subscriber := secureclient.NewSecureClient(
		broker,
		&abe.PublisherABE{},
		&abe.SubscriberABE{},
		&aescryptography.AESCryptography{},
		nil,
		goodPrivKeyBytes,
	)

	called := false
	if err := subscriber.SubscribeSecure(testTopic, 0, func(topic string, pt []byte) {
		called = true
	}); err != nil {
		t.Fatalf("SubscribeSecure() error: %v", err)
	}

	if err := publisher.PublishSecure(testTopic, 0, false, []byte("payload"), testPolicy); err != nil {
		t.Fatalf("PublishSecure() error: %v", err)
	}

	if called {
		t.Fatalf("handler should not be called when envelope policy is tampered (AES-GCM auth must fail)")
	}
}

func TestSecureClient_EndToEnd_TamperedEnvelopeVersion_FailsAESAuth(t *testing.T) {
	pubKeyBytes, goodPrivKeyBytes, _ := setupABEKeys(t)

	broker := newMemMQTT()

	// Tamper version => AAD mismatch => AES must fail
	broker.onPublish = func(topic string, payload []byte) []byte {
		var env internal.Envelope
		if err := json.Unmarshal(payload, &env); err != nil {
			return payload
		}
		env.Version = "v2"
		b, err := json.Marshal(env)
		if err != nil {
			return payload
		}
		return b
	}

	publisher := secureclient.NewSecureClient(
		broker,
		&abe.PublisherABE{},
		&abe.SubscriberABE{},
		&aescryptography.AESCryptography{},
		pubKeyBytes,
		nil,
	)

	subscriber := secureclient.NewSecureClient(
		broker,
		&abe.PublisherABE{},
		&abe.SubscriberABE{},
		&aescryptography.AESCryptography{},
		nil,
		goodPrivKeyBytes,
	)

	called := false
	if err := subscriber.SubscribeSecure(testTopic, 0, func(topic string, pt []byte) {
		called = true
	}); err != nil {
		t.Fatalf("SubscribeSecure() error: %v", err)
	}

	if err := publisher.PublishSecure(testTopic, 0, false, []byte("payload"), testPolicy); err != nil {
		t.Fatalf("PublishSecure() error: %v", err)
	}

	if called {
		t.Fatalf("handler should not be called when envelope version is tampered (AES-GCM auth must fail)")
	}
}
