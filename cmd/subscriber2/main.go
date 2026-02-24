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

	topic := "topicX"

	// Simulates a subscriber that does not hold the correct key.
	// In Step 3 this becomes: attributes that don't satisfy the CP-ABE policy.
	wrongKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatalf("[SUB-2] Key generation error: %v", err)
	}

	if err := client.Subscribe(topic, 0, func(message mqttClient.Message) {

		var envelope internal.Envelope
		if err := json.Unmarshal(message.Payload, &envelope); err != nil {
			log.Printf("[SUB-2] Bad envelope: %v", err)
			return
		}

		nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
		if err != nil {
			log.Printf("[SUB-2] Bad nonce: %v", err)
			return
		}

		ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
		if err != nil {
			log.Printf("[SUB-2] Bad ciphertext: %v", err)
			return
		}

		aad := crypto.BuildAAD(message.Topic, envelope.Policy, envelope.Version)

		_, err = crypto.Decrypt(wrongKey, nonce, ciphertext, aad)
		log.Printf("[SUB-2] ========================================")
		log.Printf("[SUB-2] Message received")
		log.Printf("[SUB-2]   Topic     : %s", message.Topic)
		log.Printf("[SUB-2]   Policy    : %s", envelope.Policy)
		log.Printf("[SUB-2]   AAD       : %s", aad)
		log.Printf("[SUB-2]   Nonce     : %s", envelope.Nonce)
		log.Printf("[SUB-2]   Ciphertext: %s...", envelope.Ciphertext[:20])
		if err != nil {
			log.Printf("[SUB-2]   Result    : ✗ DECRYPTION FAILED (as expected — wrong key)")
		} else {
			log.Fatalf("[SUB-2]   Result    : SECURITY ERROR — decryption succeeded with wrong key!")
		}
		log.Printf("[SUB-2] ========================================")
	}); err != nil {
		log.Fatalf("[SUB-2] Subscribe error: %v", err)
	}

	select {}
}
