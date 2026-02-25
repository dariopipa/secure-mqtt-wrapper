package internal

const SupportedVersion = "v1"

type Envelope struct {
	Version       string `json:"version"`
	Policy        string `json:"policy"`
	CPCipherText  string `json:"cp_ciphertext"`
	IV            string `json:"iv"`
	AESCiphertext string `json:"aes_ciphertext"`
}
