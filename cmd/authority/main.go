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

const keysDir = "/keys"

func main() {
	log.SetPrefix("[AUTHORITY] ")
	log.SetFlags(0)

	var (
		doSetup   = flag.Bool("setup", false, "generate and persist public.key and master.key in /keys")
		doIssue   = flag.Bool("issue", false, "issue a private key using /keys/master.key")
		force     = flag.Bool("force", false, "overwrite existing public.key/master.key (setup only)")
		outFile   = flag.String("out", "", "output key filename to write under /keys (issue only), e.g. sub1.key")
		attrsJSON = flag.String("attrs-json", "", `attributes as JSON object, e.g. {"role":"operator","site":"rome"} (issue only)`)
	)
	flag.Parse()

	// exactly one mode
	if (*doSetup && *doIssue) || (!*doSetup && !*doIssue) {
		usageAndExit("choose exactly one: --setup or --issue")
	}

	if *doSetup {
		if err := setupPersisted(*force); err != nil {
			log.Fatalf("Setup failed: %v", err)
		}
		log.Println("Setup complete. Wrote /keys/public.key and /keys/master.key.")
		return
	}

	// issue mode
	if *outFile == "" {
		usageAndExit("--out is required in --issue mode")
	}
	if *attrsJSON == "" {
		usageAndExit("--attrs-json is required in --issue mode")
	}

	attrs, err := parseAttrsJSON(*attrsJSON)
	if err != nil {
		log.Fatalf("Invalid --attrs-json: %v", err)
	}

	masterSecretKey, err := loadMasterSecretKey()
	if err != nil {
		log.Fatalf("Failed to load master key: %v", err)
	}

	// IMPORTANT: your critical function (unchanged) writes the key to /keys/<outFile>
	if err := issueKey(masterSecretKey, attrs, *outFile); err != nil {
		log.Fatalf("%v", err)
	}

	// copy/paste output (base64) AFTER writing
	keyPath := filepath.Join(keysDir, *outFile)
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		log.Fatalf("Issued key written, but failed to read back for base64 printing: %v", err)
	}

	fmt.Printf("WROTE: %s\n", keyPath)
	fmt.Printf("PRIVATE_KEY_BASE64: %s\n", base64.StdEncoding.EncodeToString(keyBytes))
}

func usageAndExit(msg string) {
	fmt.Fprintf(os.Stderr, "error: %s\n\n", msg)
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "  authority --setup [--force]\n")
	fmt.Fprintf(os.Stderr, "  authority --issue --out <file.key> --attrs-json '{\"role\":\"operator\",\"site\":\"rome\"}'\n")
	os.Exit(2)
}

func setupPersisted(force bool) error {
	// ensure /keys exists
	if err := os.MkdirAll(keysDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", keysDir, err)
	}

	publicPath := filepath.Join(keysDir, "public.key")
	masterPath := filepath.Join(keysDir, "master.key")

	publicExists := fileExists(publicPath)
	masterExists := fileExists(masterPath)

	if !force {
		// If both exist, keep them stable and do nothing.
		if publicExists && masterExists {
			return nil
		}
		// If only one exists, refuse to avoid mismatched pairs.
		if publicExists || masterExists {
			return fmt.Errorf("partial key material exists (public.key/master.key). Delete both or rerun with --force")
		}
	}

	// Generate fresh setup
	publicKey, masterSecretKey, err := tkn20.Setup(rand.Reader)
	if err != nil {
		return fmt.Errorf("Setup failed: %w", err)
	}

	// Serialize and persist using your existing writeKey for public.key
	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("Failed to marshal public key: %w", err)
	}
	if err := writeKey("public.key", publicKeyBytes); err != nil {
		return err
	}

	// Persist master key (new helper; minimal necessity)
	masterBytes, err := masterSecretKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("Failed to marshal master secret key: %w", err)
	}
	if err := writeMasterKey(masterBytes); err != nil {
		return err
	}

	return nil
}

func loadMasterSecretKey() (tkn20.SystemSecretKey, error) {
	var masterSecretKey tkn20.SystemSecretKey

	path := filepath.Join(keysDir, "master.key")
	data, err := os.ReadFile(path)
	if err != nil {
		return masterSecretKey, fmt.Errorf("read %s: %w", path, err)
	}

	if err := masterSecretKey.UnmarshalBinary(data); err != nil {
		return masterSecretKey, fmt.Errorf("unmarshal master secret key: %w", err)
	}

	return masterSecretKey, nil
}

func writeMasterKey(data []byte) error {
	// minimal: create /keys and write master.key
	if err := os.MkdirAll(keysDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", keysDir, err)
	}

	path := filepath.Join(keysDir, "master.key")
	// tighter perms than public/sub keys
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func parseAttrsJSON(raw string) (map[string]string, error) {
	// expects {"role":"operator","site":"rome"}
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

/*
CRITICAL FUNCTIONS: UNCHANGED (verbatim)
*/

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
