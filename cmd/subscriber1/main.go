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
		ClientID:  "subscriber-1",
	})
	if err != nil {
		log.Fatalf("connect error: %v", err)
	}

	fmt.Println("Subscriber 1 connected (EXAMPLE --- AUTHORIZED)")

	topic := "topicX"

	if err := client.Subscribe(topic, 0, func(message mqttClient.Message) {

		var envelope internal.Envelope
		if err := json.Unmarshal(message.Payload, &envelope); err != nil {
			log.Printf("[Sub-1] bad envelope: %v", err)
			return
		}

		nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
		if err != nil {
			log.Printf("[Sub-1] bad nonce: %v", err)
			return
		}

		ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
		if err != nil {
			log.Printf("[Sub-1] bad ciphertext: %v", err)
			return
		}

		plaintext, err := crypto.Decrypt(crypto.HardcodedKey, nonce, ciphertext)
		if err != nil {
			log.Printf("[Sub-1] decryption failed: %v", err)
			return
		}

		fmt.Printf("[Subscriber 1] ✓ Decrypted: %s\n", plaintext)
	}); err != nil {
		log.Fatalf("subscribe error: %v", err)
	}

	select {}
}
