package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"securemqtt/internal/abe"
	aescryptography "securemqtt/internal/aes"
	"securemqtt/internal/clientmqtt"
	"securemqtt/internal/secureclient"
)

const (
	attrKeyPath = "/keys/sub1.key"
	brokerURL   = "tcp://broker:1883"
	clientID    = "subscriber-1"
	topic       = "topicX"
)

func main() {

	privateKeyBytes, err := waitForKey(attrKeyPath)
	if err != nil {
		log.Fatalf("Failed to load attribute key: %v", err)
	}

	// Create & connect to MQTT client
	client, err := clientmqtt.NewMQTT(brokerURL, clientID)
	if err != nil {
		log.Fatalf("[SUB-1] Failed to connect to broker: %v", err)
	}

	secureClient := secureclient.NewSecureClient(client, &abe.PublisherABE{}, &abe.SubscriberABE{},
		&aescryptography.AESCryptography{}, nil, privateKeyBytes)

	if err := secureClient.SubscribeSecure(topic, 0, func(t string, plaintext []byte) {
		log.Printf("  Result    : ✓ SUCCESS")
		log.Printf("  Topic     : %s", t)
		log.Printf("  Plaintext : %s", plaintext)
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
