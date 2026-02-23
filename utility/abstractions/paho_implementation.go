package abstractions

import (
	"fmt"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
)

type pahoClient struct {
	client paho.Client
}

func newPahoClient(config Config) (Client, error) {
	options := paho.NewClientOptions().
		AddBroker(config.BrokerURL).
		SetClientID(config.ClientID).
		SetAutoReconnect(true)

	underlyingClient := paho.NewClient(options)

	connectToken := underlyingClient.Connect()

	if !connectToken.WaitTimeout(10 * time.Second) {
		return nil, fmt.Errorf("connect timeout")
	}
	if connectToken.Error() != nil {
		return nil, connectToken.Error()
	}

	return &pahoClient{client: underlyingClient}, nil
}

func (p *pahoClient) Publish(topic string, qos byte, retained bool, payload []byte) error {
	token := p.client.Publish(topic, qos, retained, payload)

	if !token.WaitTimeout(10 * time.Second) {
		return fmt.Errorf("publish timeout")
	}

	return token.Error()
}

func (p *pahoClient) Subscribe(topic string, qos byte, handler Handler) error {
	token := p.client.Subscribe(topic, qos, func(_ paho.Client, msg paho.Message) {
		handler(Message{
			Topic:   msg.Topic(),
			Payload: msg.Payload(),
		})
	})

	if !token.WaitTimeout(10 * time.Second) {
		return fmt.Errorf("subscribe timeout")
	}

	return token.Error()
}
