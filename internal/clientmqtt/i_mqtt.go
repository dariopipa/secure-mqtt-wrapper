package clientmqtt

import "securemqtt/internal"

type IMQTT interface {
	Publish(topic string, qos byte, retained bool, payload []byte) error
	Subscribe(topic string, qos byte, handler func(internal.Message)) error
}
