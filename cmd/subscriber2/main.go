package main

import (
	"fmt"
	"log"

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

	fmt.Println("Subscriber 2 connected")

	topic := "topicX"

	if err := client.Subscribe(topic, 0, func(message mqttClient.Message) {
		fmt.Printf("[Subscriber 2] Received: %s\n", string(message.Payload))
	}); err != nil {
		log.Fatalf("subscribe error: %v", err)
	}

	select {}
}
