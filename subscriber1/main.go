package main

import (
	"fmt"
	"log"

	mqttClient "securemqtt/utility/abstractions"
)

func main() {
	client, err := mqttClient.NewMQTTClient(mqttClient.Config{
		BrokerURL: "tcp://broker:1883",
		ClientID:  "subscriber-1",
	})
	if err != nil {
		log.Fatalf("connect error: %v", err)
	}

	fmt.Println("Subscriber 1 connected")

	topic := "topicX"

	if err := client.Subscribe(topic, 0, func(message mqttClient.Message) {
		fmt.Printf("[Subscriber 1] Received: %s\n", string(message.Payload))
	}); err != nil {
		log.Fatalf("subscribe error: %v", err)
	}

	select {}
}
