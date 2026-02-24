package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
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
		log.Fatalf("connect error: %v", err)
	}

	fmt.Println("Subscriber 2 connected (UNAUTHORIZED --— wrong key)")

	topic := "topicX"

	// Simulates a subscriber that does not hold the correct key.
	// In Step 3 this becomes: attributes that don't satisfy the CP-ABE policy.
	wrongKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatalf("key generation error: %v", err)
	}

	if err := client.Subscribe(topic, 0, func(message mqttClient.Message) {

		var envelope internal.Envelope
		if err := json.Unmarshal(message.Payload, &envelope); err != nil {
			log.Printf("[Sub-2] bad envelope: %v", err)
			return
		}

		nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
		if err != nil {
			log.Printf("[Sub-2] bad nonce: %v", err)
			return
		}

		ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
		if err != nil {
			log.Printf("[Sub-2] bad ciphertext: %v", err)
			return
		}

		_, err = crypto.Decrypt(wrongKey, nonce, ciphertext)
		if err != nil {
			fmt.Printf("[Subscriber 2] ✗ Cannot decrypt (unauthorized): %v\n", err)
			return
		}

		log.Fatal("[Sub-2] SECURITY ERROR: decryption succeeded with wrong key!")
	}); err != nil {
		log.Fatalf("subscribe error: %v", err)
	}

	select {}
}
