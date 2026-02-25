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
	publicKeyPath = "/keys/public.key"
	brokerURL     = "tcp://broker:1883"
	clientID      = "publisher-client"
	topic         = "topicX"
	policy        = "(role: operator) and (site: rome)"
)

func main() {

	publicKeyBytes, err := waitForKey(publicKeyPath)
	if err != nil {
		log.Fatalf("Failed to load public key: %v", err)
	}

	// Create & connect MQTT client using wrapper through broker address & client ID
	client, err := clientmqtt.NewMQTT(brokerURL, clientID)
	if err != nil {
		log.Fatalf("[PUBLISHER] Failed to connect to broker: %v", err)
	}

	secureClient := secureclient.NewSecureClient(client, &abe.PublisherABE{}, &abe.SubscriberABE{},
		&aescryptography.AESCryptography{}, publicKeyBytes, nil)

	for {
		plaintext := []byte(fmt.Sprintf("Message at %s", time.Now().Format(time.RFC3339)))

		// Publish payload to topic
		if err := secureClient.PublishSecure(topic, 0, false, plaintext, policy); err != nil {
			log.Printf("[PUBLISHER] Failed to publish: %v", err)
		} else {
			log.Printf("[PUBLISHER] JSON Envelope: ")
		}

		time.Sleep(5 * time.Second)
	}
}

// Loops infinitely until the specified key file is available
// Because otherwise, the container might start before the authority has generated the keys
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
