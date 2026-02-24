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
		ClientID:  "subscriber-1",
	})
	if err != nil {
		log.Fatalf("[SUB-1] Failed to connect to broker: %v", err)
	}

	log.Println("[SUB-1] Connected to broker")
	log.Println("[SUB-1] Status    : AUTHORIZED (holds correct key)")
	log.Println("[SUB-1] Listening : topicX")

	topic := "topicX"

	if err := client.Subscribe(topic, 0, func(message mqttClient.Message) {

		var envelope internal.Envelope
		if err := json.Unmarshal(message.Payload, &envelope); err != nil {
			log.Printf("[SUB-1] Bad envelope: %v", err)
			return
		}

		nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
		if err != nil {
			log.Printf("[SUB-1] Bad nonce: %v", err)
			return
		}

		ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
		if err != nil {
			log.Printf("[SUB-1] Bad ciphertext: %v", err)
			return
		}

		aad := crypto.BuildAAD(message.Topic, envelope.Policy, envelope.Version)

		plaintext, err := crypto.Decrypt(crypto.HardcodedKey, nonce, ciphertext, aad)
		log.Printf("[SUB-1] ========================================")
		log.Printf("[SUB-1] Message received")
		log.Printf("[SUB-1]   Topic     : %s", message.Topic)
		log.Printf("[SUB-1]   Policy    : %s", envelope.Policy)
		log.Printf("[SUB-1]   AAD       : %s", aad)
		log.Printf("[SUB-1]   Nonce     : %s", envelope.Nonce)
		log.Printf("[SUB-1]   Ciphertext: %s...", envelope.Ciphertext[:20])
		if err != nil {
			log.Printf("[SUB-1]   Result    : ✗ DECRYPTION FAILED — %v", err)
			return
		} else {
			log.Printf("[SUB-1]   Result    : ✓ SUCCESS")
			log.Printf("[SUB-1]   Plaintext : %s", plaintext)
		}
		log.Printf("[SUB-1] ========================================")
	}); err != nil {
		log.Fatalf("[SUB-1] Subscribe error: %v", err)
	}

	select {}
}
