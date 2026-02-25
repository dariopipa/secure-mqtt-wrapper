package clientmqtt

import (
	"fmt"
	"securemqtt/internal"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
)

type MQTT struct {
	mqttClient paho.Client
}

// Constructor
func NewMQTT(brokerURL string, clientID string) (IMQTT, error) {

	options := paho.NewClientOptions().
		AddBroker(brokerURL).
		SetClientID(clientID).
		SetAutoReconnect(true)

	mqttClient := paho.NewClient(options)

	connectToken := mqttClient.Connect()

	if !connectToken.WaitTimeout(10 * time.Second) {
		return nil, fmt.Errorf("connect timeout")
	}
	if connectToken.Error() != nil {
		return nil, connectToken.Error()
	}

	return &MQTT{mqttClient: mqttClient}, nil
}

func (strct *MQTT) Publish(topic string, qos byte, retained bool, payload []byte) error {

	token := strct.mqttClient.Publish(topic, qos, retained, payload)

	if !token.WaitTimeout(10 * time.Second) {
		return fmt.Errorf("publish timeout")
	}

	return token.Error()
}

func (strct *MQTT) Subscribe(topic string, qos byte, handler func(internal.Message)) error {

	token := strct.mqttClient.Subscribe(topic, qos, func(_ paho.Client, msg paho.Message) {
		handler(internal.Message{
			Topic:    msg.Topic(),
			Envelope: msg.Payload(),
		})
	})

	if !token.WaitTimeout(10 * time.Second) {
		return fmt.Errorf("subscribe timeout")
	}

	return token.Error()
}
