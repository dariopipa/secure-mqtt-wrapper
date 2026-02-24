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

	// Create & connect MQTT client using wrapper through:
	// 1. Broker address
	// 2. Client ID
	client, err := mqttClient.NewMQTTClient(mqttClient.Config{
		BrokerURL: "tcp://broker:1883",
		ClientID:  "publisher-client",
	})
	if err != nil {
		log.Fatalf("[PUBLISHER] Failed to connect to broker: %v", err)
	}

	log.Println("[PUBLISHER] Connected to broker.")

	// MQTT topic
	topic := "topicX"

	// Metadata bound to AAD, which will enforce access control
	policy := "role:operator AND site:rome"

	// Publish loop
	// 1. Create message
	// 2. Encrypt it
	// 3. Wrap it in an envelope
	// 4. Marshal
	// 5. Publish
	// 6. Repeat
	for {
		plaintext := []byte(fmt.Sprintf("Message at %s", time.Now().Format(time.RFC3339)))

		// Bind ciphertext to version, topic & policy
		aad := crypto.BuildAAD(topic, policy, "v1")

		// Encrypt using AES
		iv, ciphertext, err := crypto.Encrypt(crypto.HardcodedKey, plaintext, aad)
		if err != nil {
			log.Printf("[PUBLISHER] Encryption error: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Envelope will be transmitted as MQTT payload
		// Ensure encoding is done to turn arbitrary binary bytes into safe printable text
		envelope := internal.Envelope{
			Version:    "v1",
			Policy:     policy,
			Nonce:      base64.StdEncoding.EncodeToString(iv),
			Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		}

		envelopeJSON, err := json.Marshal(envelope)
		if err != nil {
			log.Printf("[PUBLISHER] Failed to marshal envelope: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Publish payload to topic
		if err := client.Publish(topic, 0, false, envelopeJSON); err != nil {
			log.Printf("[PUBLISHER] Failed to publish: %v", err)
		} else {
			log.Printf("[PUBLISHER] JSON Envelope: %s", envelopeJSON)
		}

		time.Sleep(5 * time.Second)
	}
}
