package main

import (
	"fmt"
	"log"
	"time"

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
		message := fmt.Sprintf("Message at %s", time.Now().Format(time.RFC3339))

		if err := client.Publish(topic, 0, false, []byte(message)); err != nil {
			log.Printf("publish error: %v", err)
		} else {
			fmt.Println("Published:", message)
		}

		time.Sleep(5 * time.Second)
	}
}
