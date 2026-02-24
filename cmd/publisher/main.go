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
		log.Fatalf("connect error: %v", err)
	}

	fmt.Println("Publisher connected")

	topic := "topicX"

	for {
		plaintext := fmt.Sprintf("Message at %s", time.Now().Format(time.RFC3339))

		nonce, ciphertext, err := crypto.Encrypt(crypto.HardcodedKey, []byte(plaintext))
		if err != nil {
			log.Printf("encrypt error: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		envelope := internal.Envelope{
			Version:    "v1",
			Nonce:      base64.StdEncoding.EncodeToString(nonce),
			Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		}

		raw, err := json.Marshal(envelope)
		if err != nil {
			log.Printf("marshal error: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		if err := client.Publish(topic, 0, false, raw); err != nil {
			log.Printf("publish error: %v", err)
		} else {
			fmt.Println("Published:", plaintext)
		}

		time.Sleep(5 * time.Second)
	}
}
