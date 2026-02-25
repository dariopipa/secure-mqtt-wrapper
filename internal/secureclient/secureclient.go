package secureclient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	"securemqtt/internal"
	"securemqtt/internal/abe"
	aescryptography "securemqtt/internal/aes"
	"securemqtt/internal/clientmqtt"
)

type SecureClient struct {
	mqttClient      clientmqtt.IMQTT
	publisherABE    abe.IPublisherABE
	subscriberABE   abe.ISubscriberABE
	aesCryptography aescryptography.IAESCryptography
	publicKeyBytes  []byte
	privateKeyBytes []byte
}

// Constructor
func NewSecureClient(
	mqttClient clientmqtt.IMQTT,
	publisherABE abe.IPublisherABE,
	subscriberABE abe.ISubscriberABE,
	aesCryptography aescryptography.IAESCryptography,
	publicKeyBytes []byte,
	privateKeyBytes []byte,
) *SecureClient {
	return &SecureClient{
		mqttClient:      mqttClient,
		publisherABE:    publisherABE,
		subscriberABE:   subscriberABE,
		aesCryptography: aesCryptography,
		publicKeyBytes:  publicKeyBytes,
		privateKeyBytes: privateKeyBytes,
	}
}

// Encrypts plaintext under policy & publishes envelope to topic
func (strct *SecureClient) PublishSecure(topic string, qos byte, retained bool,
	plaintext []byte, policy string) error {

	// Generate session key
	sessionKey, err := strct.aesCryptography.GenerateKey()
	if err != nil {
		return fmt.Errorf("%s PublishSecure: key generation.", err)
	}

	// Encrypt session key under with CP-ABE under some policy
	cpCipherTextBytes, err := strct.publisherABE.EncryptKey(strct.publicKeyBytes, policy, sessionKey)
	if err != nil {
		return fmt.Errorf("%s PublishSecure: ABE encrypt.", err)
	}

	// Build AAD as "version|topic|policy", then encrypt plaintext with AES
	aad := strct.aesCryptography.BuildAAD(topic, policy, internal.SupportedVersion)

	iv, aesCipherTextBytes, err := strct.aesCryptography.Encrypt(sessionKey, plaintext, aad)
	if err != nil {
		return fmt.Errorf("%s PublishSecure: AES encrypt", err)
	}

	// Build & serialize envelope
	envelope := internal.Envelope{
		Version:       internal.SupportedVersion,
		Policy:        policy,
		CPCipherText:  base64.StdEncoding.EncodeToString(cpCipherTextBytes),
		IV:            base64.StdEncoding.EncodeToString(iv),
		AESCiphertext: base64.StdEncoding.EncodeToString(aesCipherTextBytes),
	}

	// Turn into JSON
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("%s PublishSecure: marshal.", err)
	}

	// Publish to MQTT
	return strct.mqttClient.Publish(topic, qos, retained, envelopeJSON)
}

// Decrypts received envelope & obtain plaintext
func (strct *SecureClient) SubscribeSecure(topic string, qos byte,
	handler func(topic string, plaintext []byte)) error {

	return strct.mqttClient.Subscribe(topic, qos, func(msg internal.Message) {

		var envelope internal.Envelope
		if err := json.Unmarshal(msg.Envelope, &envelope); err != nil {
			log.Printf("%s invalid envelope JSON.", err)
			return
		}

		// Decode back to bytes
		cpCipherTextBytes, err := base64.StdEncoding.DecodeString(envelope.CPCipherText)
		if err != nil {
			log.Printf("%s base64 decode encrypted_key.", err)
			return
		}

		// Decrypt session key with CP-ABE
		sessionKey, err := strct.subscriberABE.DecryptKey(strct.privateKeyBytes, cpCipherTextBytes)
		if err != nil {
			log.Printf("%s   Result    : ✗ DECRYPTION FAILED — attributes do not satisfy policy.", err)
			return
		}

		// Decode back to bytes
		iv, err := base64.StdEncoding.DecodeString(envelope.IV)
		if err != nil {
			log.Printf("%s base64 decode nonce.", err)
			return
		}
		aesCipherTextBytes, err := base64.StdEncoding.DecodeString(envelope.AESCiphertext)
		if err != nil {
			log.Printf("%s base64 decode ciphertext.", err)
			return
		}

		// Rebuild AAD
		aad := strct.aesCryptography.BuildAAD(msg.Topic, envelope.Policy, envelope.Version)

		// Decrypt ciphertext with AES
		plaintext, err := strct.aesCryptography.Decrypt(sessionKey, iv, aesCipherTextBytes, aad)
		if err != nil {
			log.Printf("%s   Result    : ✗ AES-GCM auth failed.", err)
			return
		}

		handler(msg.Topic, plaintext)
	})
}
