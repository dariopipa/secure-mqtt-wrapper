package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cloudflare/circl/abe/cpabe/tkn20"
)

const (
	keysDir       = "/keys"
	publicKeyFile = "public.key"
	masterKeyFile = "master.key"
)

func main() {
	log.SetPrefix("[AUTHORITY] ")
	log.SetFlags(0)

	// CLI flags
	var (
		doSetup   = flag.Bool("setup", false, "generate and persist public.key and master.key in /keys")
		doIssue   = flag.Bool("issue", false, "issue a private key using /keys/master.key")
		force     = flag.Bool("force", false, "overwrite existing public.key/master.key (setup only)")
		outFile   = flag.String("out", "", "output key filename to write under /keys (issue only), e.g. sub1.key")
		attrsJSON = flag.String("attrs-json", "", `attributes as JSON object, e.g. {"role":"operator","site":"rome"} (issue only)`)
	)
	flag.Parse()

	// This will enforce that exactly one of --setup or --issue is chosen
	if (*doSetup && *doIssue) || (!*doSetup && !*doIssue) {
		usageAndExit("choose exactly one: --setup or --issue")
	}

	// Setup mode generate & persist the public and master key.
	// If they already exist the command will be ignored.
	if *doSetup {
		if err := setupPersisted(*force); err != nil {
			log.Fatalf("Setup failed: %v", err)
		}
		log.Println("Setup complete. Wrote /keys/public.key and /keys/master.key.")
		return
	}

	// Issue mode,will validate the necessary flags regarding the output file and attributes JSON, then will generate a private key for the given attributes and write it to the specified file under /keys.
	if *outFile == "" {
		usageAndExit("--out is required in --issue mode")
	}
	if *attrsJSON == "" {
		usageAndExit("--attrs-json is required in --issue mode")
	}

	// Parse the attributes JSON into a map[string]string
	attrs, err := parseAttrsJSON(*attrsJSON)
	if err != nil {
		log.Fatalf("Invalid --attrs-json: %v", err)
	}

	// Load the master secret key
	masterSecretKey, err := loadMasterSecretKey()
	if err != nil {
		log.Fatalf("Failed to load master key: %v", err)
	}

	// Generate and save the private keys for the given attributes
	if err := issueKey(masterSecretKey, attrs, *outFile); err != nil {
		log.Fatalf("%v", err)
	}

	// Read the generated key back to print in the CLI
	keyPath := filepath.Join(keysDir, *outFile)
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		log.Fatalf("Issued key written, but failed to read back for base64 printing: %v", err)
	}

	fmt.Printf("WROTE: %s\n", keyPath)
	fmt.Printf("PRIVATE_KEY_BASE64: %s\n", base64.StdEncoding.EncodeToString(keyBytes))
}

// setupPersisted generates system keys and writes them to disk.
// It avoids overwriting existing keys unless --force flag is used.
func setupPersisted(force bool) error {
	if err := os.MkdirAll(keysDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", keysDir, err)
	}

	publicPath := filepath.Join(keysDir, publicKeyFile)
	masterPath := filepath.Join(keysDir, masterKeyFile)

	publicExists := fileExists(publicPath)
	masterExists := fileExists(masterPath)

	// Check if the --force flag has been passed to prevent overwrites of the keys
	if !force {
		if publicExists && masterExists {
			return nil
		}

		if publicExists || masterExists {
			return fmt.Errorf("partial key material exists (public.key/master.key). Delete both or rerun with --force")
		}
	}

	// Generate the public and master secret keys
	publicKey, masterSecretKey, err := tkn20.Setup(rand.Reader)
	if err != nil {
		return fmt.Errorf("Setup failed: %w", err)
	}

	// Serialize & store the public key
	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("Failed to marshal public key: %w", err)
	}
	if err := writeKey(publicKeyFile, publicKeyBytes); err != nil {
		return err
	}

	// Serialize & store the master secret key
	masterBytes, err := masterSecretKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("Failed to marshal master secret key: %w", err)
	}
	if err := writeKey(masterKeyFile, masterBytes); err != nil {
		return err
	}

	return nil
}

// Loads master key from disk and deserializes it.
func loadMasterSecretKey() (tkn20.SystemSecretKey, error) {
	var masterSecretKey tkn20.SystemSecretKey

	path := filepath.Join(keysDir, masterKeyFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return masterSecretKey, fmt.Errorf("read %s: %w", path, err)
	}

	if err := masterSecretKey.UnmarshalBinary(data); err != nil {
		return masterSecretKey, fmt.Errorf("unmarshal master secret key: %w", err)
	}

	return masterSecretKey, nil
}

// Parses JSON attribute string into map[string]string. Will validate that keys and values are non-empty strings.
func parseAttrsJSON(raw string) (map[string]string, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("attribute %q must be a string", k)
		}
		if k == "" || s == "" {
			return nil, fmt.Errorf("attribute keys and values must be non-empty strings")
		}
		out[k] = s
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty attribute set")
	}
	return out, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Generates a subscriber private key from given attributes
// and writes it to the specified file.
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

// Writes the key to the specified file
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

func usageAndExit(msg string) {
	fmt.Fprintf(os.Stderr, "error: %s\n\n", msg)
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "  authority --setup [--force]\n")
	fmt.Fprintf(os.Stderr, "  authority --issue --out <file.key> --attrs-json '{\"role\":\"operator\",\"site\":\"rome\"}'\n")
	os.Exit(2)
}
