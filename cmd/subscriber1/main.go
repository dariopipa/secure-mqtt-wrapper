package main

import (
	"encoding/base64"
	"encoding/json"
	"log"

	"securemqtt/internal"
	"securemqtt/internal/crypto"
	mqttClient "securemqtt/internal/mqtt"
)

func main() {

	// Create & connect to MQTT client
	client, err := mqttClient.NewMQTTClient(mqttClient.Config{
		BrokerURL: "tcp://broker:1883",
		ClientID:  "subscriber-1",
	})
	if err != nil {
		log.Fatalf("[SUB-1] Failed to connect to broker: %v", err)
	}

	log.Println("[SUB-1] Connected to broker")
	log.Println("[SUB-1] Status    : AUTHORIZED (holds correct key)")
	log.Println("[SUB-1] Listening : topicX")

	// MQTT Topic
	topic := "topicX"

	// Subscribe to it with a QoS of 0
	// Call a handler function for each message received
	if err := client.Subscribe(topic, 0, func(message mqttClient.Message) {

		// Parse the JSON payload into Envelope struct
		var envelope internal.Envelope
		if err := json.Unmarshal(message.Payload, &envelope); err != nil {
			log.Printf("[SUB-1] Bad envelope: %v", err)
			return
		}

		// Decode Base64 IV into raw bytes
		iv, err := base64.StdEncoding.DecodeString(envelope.Nonce)
		if err != nil {
			log.Printf("[SUB-1] Bad nonce: %v", err)
			return
		}

		// Decode Base64 ciphertext string into raw bytes
		ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
		if err != nil {
			log.Printf("[SUB-1] Bad ciphertext: %v", err)
			return
		}

		// Rebuild AAD
		aad := crypto.BuildAAD(message.Topic, envelope.Policy, envelope.Version)

		// Decrypt
		plaintext, err := crypto.Decrypt(crypto.HardcodedKey, iv, ciphertext, aad)
		if err != nil {
			log.Printf("[SUB-1]   Result    : ✗ DECRYPTION FAILED — %v", err)
			return
		} else {
			log.Printf("[SUB-1]   Result    : ✓ SUCCESS")
			log.Printf("[SUB-1]   Plaintext : %s", plaintext)
		}
	}); err != nil {
		log.Fatalf("[SUB-1] Subscribe error: %v", err)
	}

	select {}
}
