package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cloudflare/circl/abe/cpabe/tkn20"
)

const keysDir = "/keys"

func main() {
	log.SetPrefix("[AUTHORITY] ")

	// Utilize the provided setup function to generate the publicKey & masterSecretKey
	publicKey, masterSecretKey, err := tkn20.Setup(rand.Reader)
	if err != nil {
		log.Fatalf("Setup failed: %v", err)
	}

	// Serialize public key to write in into disk
	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
	}

	// Write to /keys/public.key
	// This will be available to everyone
	if err := writeKey("public.key", publicKeyBytes); err != nil {
		log.Fatalf("%v", err)
	}

	// Generate 2 private keys
	// One allows decryption, other doesn't
	if err := issueKey(masterSecretKey, map[string]string{
		"role": "operator",
		"site": "rome",
	}, "sub1.key"); err != nil {
		log.Fatalf("%v", err)
	}
	if err := issueKey(masterSecretKey, map[string]string{
		"role": "guest",
		"site": "milan",
	}, "sub2.key"); err != nil {
		log.Fatalf("%v", err)
	}

	log.Println("All keys written. Authority exiting.")
}

func issueKey(masterSecretKey tkn20.SystemSecretKey, attributeList map[string]string, filename string) error {

	var attributes tkn20.Attributes
	attributes.FromMap(attributeList)

	privateKey, err := masterSecretKey.KeyGen(rand.Reader, attributes)
	if err != nil {
		return fmt.Errorf("KeyGen for %s failed: %w", filename, err)
	}

	privateKeyBytes, err := privateKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal AttributeKey for %s: %w", filename, err)
	}

	if err := writeKey(filename, privateKeyBytes); err != nil {
		return err
	}

	return nil
}

func writeKey(name string, data []byte) error {

	if err := os.MkdirAll(keysDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", keysDir, err)
	}

	path := filepath.Join(keysDir, name)
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
