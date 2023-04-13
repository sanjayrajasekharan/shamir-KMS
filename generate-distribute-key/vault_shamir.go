package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"

	vaultShamir "github.com/hashicorp/vault/shamir"
)

func main() {
	// Parse command-line arguments
	var n, k int
	var keyType string
	flag.IntVar(&n, "n", 0, "Number of shares to split the key into")
	flag.IntVar(&k, "k", 0, "Number of shares required to reconstruct the key")
	flag.StringVar(&keyType, "keytype", "", "Type of key to generate (RSA or AES)")
	flag.Parse()

	if n < k || n <= 0 || k <= 0 {
		log.Fatalf("Invalid arguments: n and k must be positive integers such that n >= k")
	}

	var key []byte
	var err error

	// Generate key based on the chosen key type
	switch keyType {
	case "RSA":
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("Error generating RSA key pair: %v", err)
		}

		key = x509.MarshalPKCS1PrivateKey(privateKey)

		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			log.Fatalf("Error marshaling public key: %v", err)
		}

		publicKeyPem := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		})

		fmt.Printf("Public key:\n%s\n", publicKeyPem)

	case "AES":
		// Generate a random key of 32 bytes
		key = make([]byte, 32)
		_, err = rand.Read(key)
		if err != nil {
			log.Fatalf("Error generating random AES key: %v", err)
		}
		fmt.Printf("Original key: %s\n", hex.EncodeToString(key))

	default:
		log.Fatalf("Invalid key type: must be 'RSA' or 'AES'")
	}

	// Split the key using Shamir's Secret Sharing
	shares, err := vaultShamir.Split(key, n, k)
	if err != nil {
		log.Fatalf("Error splitting key: %v", err)
	}

	fmt.Println("Shares:")
	for i, share := range shares {
		fmt.Printf("Share %d: %s\n", i+1, hex.EncodeToString(share))
	}

	// Combine the key using Shamir's Secret Sharing
	combinedKey, err := vaultShamir.Combine(shares[:k])
	if err != nil {
		log.Fatalf("Error combining key: %v", err)
	}

	fmt.Printf("Combined key: %s\n", hex.EncodeToString(combinedKey))
}
