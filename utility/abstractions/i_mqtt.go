package abstractions

import (
	"fmt"
	"os"
)

type Message struct {
	Topic   string
	Payload []byte
}

type Handler func(message Message)

type Config struct {
	BrokerURL string
	ClientID  string
}

type Client interface {
	Publish(topic string, qos byte, retained bool, payload []byte) error
	Subscribe(topic string, qos byte, handler Handler) error
}

func NewMQTTClient(config Config) (Client, error) {
	impl := os.Getenv("MQTT_IMPL")
	if impl == "" {
		impl = "paho" // default
	}

	switch impl {
	case "paho":
		return newPahoClient(config)
	default:
		return nil, fmt.Errorf("unsupported MQTT_IMPL=%q", impl)
	}
}
