package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"securemqtt/internal"
	"securemqtt/internal/crypto"
	mqttClient "securemqtt/internal/mqtt"
)

func main() {

	// MQTT address
	client, err := mqttClient.NewMQTTClient(mqttClient.Config{
		BrokerURL: "tcp://broker:1883",
		ClientID:  "publisher-client",
	})
	if err != nil {
		log.Fatalf("[PUBLISHER] Failed to connect to broker: %v", err)
	}

	log.Println("[PUBLISHER] Connected to broker.")

	topic := "topicX"
	policy := "role:operator AND site:rome"

	for {
		plaintext := []byte(fmt.Sprintf("Message at %s", time.Now().Format(time.RFC3339)))

		aad := crypto.BuildAAD(topic, policy, "v1")

		nonce, ciphertext, err := crypto.Encrypt(crypto.HardcodedKey, plaintext, aad)
		if err != nil {
			log.Printf("[PUBLISHER] Encryption error: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		envelope := internal.Envelope{
			Version:    "v1",
			Policy:     policy,
			Nonce:      base64.StdEncoding.EncodeToString(nonce),
			Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		}

		raw, err := json.Marshal(envelope)
		if err != nil {
			log.Printf("[PUBLISHER] Failed to marshal envelope: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		if err := client.Publish(topic, 0, false, raw); err != nil {
			log.Printf("[PUBLISHER] Failed to publish: %v", err)
		} else {
			log.Printf("[PUBLISHER] ========================================")
			log.Printf("[PUBLISHER] Published encrypted message")
			log.Printf("[PUBLISHER]   Topic     : %s", topic)
			log.Printf("[PUBLISHER]   Plaintext : %s", plaintext)
			log.Printf("[PUBLISHER]   Policy    : %s", policy)
			log.Printf("[PUBLISHER]   AAD       : %s", aad)
			log.Printf("[PUBLISHER]   Nonce     : %s", envelope.Nonce)
			log.Printf("[PUBLISHER]   Ciphertext: %s", envelope.Ciphertext[:20]+"...")
			log.Printf("[PUBLISHER] ========================================")
		}

		time.Sleep(5 * time.Second)
	}
}
