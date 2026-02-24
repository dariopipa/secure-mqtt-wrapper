package internal

type Envelope struct {
	Version    string `json:"version"`
	Policy     string `json:"policy"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}
