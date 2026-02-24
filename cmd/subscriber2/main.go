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
		ClientID:  "subscriber-2",
	})
	if err != nil {
		log.Fatalf("[SUB-2] Failed to connect to broker: %v", err)
	}

	log.Println("[SUB-2] Connected to broker at tcp://broker:1883")
	log.Println("[SUB-2] Status    : UNAUTHORIZED (wrong key — simulating policy mismatch)")
	log.Println("[SUB-2] Listening : topicX")

	// MQTT Topic
	topic := "topicX"

	// Simulates subscriber that does not hold the correct key
	wrongKey, _ := crypto.GenerateKey()

	// Subscribe to it with a QoS of 0
	// Call a handler function for each message received
	if err := client.Subscribe(topic, 0, func(message mqttClient.Message) {

		// Parse the JSON payload into Envelope struct
		var envelope internal.Envelope
		if err := json.Unmarshal(message.Payload, &envelope); err != nil {
			log.Printf("[SUB-2] Bad envelope: %v", err)
			return
		}

		// Decode Base64 IV into raw bytes
		iv, err := base64.StdEncoding.DecodeString(envelope.Nonce)
		if err != nil {
			log.Printf("[SUB-2] Bad nonce: %v", err)
			return
		}

		// Decode Base64 ciphertext string into raw bytes
		ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
		if err != nil {
			log.Printf("[SUB-2] Bad ciphertext: %v", err)
			return
		}

		// Rebuild AAD
		aad := crypto.BuildAAD(message.Topic, envelope.Policy, envelope.Version)

		// Decrypt
		plaintext, err := crypto.Decrypt(wrongKey, iv, ciphertext, aad)

		if err != nil {
			log.Printf("[SUB-2]   Result    : ✗ DECRYPTION FAILED (as expected — wrong key)")
			return

		}

		// Shouldn't reach this
		log.Fatalf("[SUB-2] SECURITY ERROR — decryption succeeded with wrong key! Plaintext: %s", plaintext)
	}); err != nil {
		log.Fatalf("[SUB-2] Subscribe error: %v", err)
	}

	select {}
}
