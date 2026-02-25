package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"securemqtt/internal/abe"
	aescryptography "securemqtt/internal/aes"
	mqttClient "securemqtt/internal/mqtt"
	"securemqtt/internal/secureclient"
)

const (
	attrKeyPath = "/keys/sub2.key"
	brokerURL   = "tcp://broker:1883"
	clientID    = "subscriber-2"
	topic       = "topicX"
)

func main() {

	privateKeyBytes, err := waitForKey(attrKeyPath)
	if err != nil {
		log.Fatalf("Failed to load attribute key: %v", err)
	}

	// Create & connect to MQTT client
	client, err := mqttClient.NewMQTTClient(mqttClient.Config{
		BrokerURL: "tcp://broker:1883",
		ClientID:  "subscriber-2",
	})
	if err != nil {
		log.Fatalf("[SUB-2] Failed to connect to broker: %v", err)
	}

	secureClient := secureclient.NewSecureClient(client, &abe.PublisherABE{}, &abe.SubscriberABE{},
		&aescryptography.AESCryptography{}, nil, privateKeyBytes)

	if err := secureClient.SubscribeSecure(topic, 0, func(t string, plaintext []byte) {
		// This handler must never be reached for an unauthorised subscriber.
		// If it is, something is seriously wrong with the ABE implementation.
		log.Fatalf("SECURITY ERROR — decryption succeeded with unauthorized key! Plaintext: %s", plaintext)
	}); err != nil {
		log.Fatalf("Subscribe error: %v", err)
	}

	select {}
}

func waitForKey(path string) ([]byte, error) {
	log.Printf("Waiting for key file: %s", path)
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			return data, nil
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("unexpected error reading %s: %w", path, err)
		}
		log.Printf("Key not ready yet, retrying in 2s...")
		time.Sleep(2 * time.Second)
	}
}
