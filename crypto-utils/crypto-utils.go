package cryptoutils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
)

// Generate a 256-bit AES key.
func GenerateAes256Key() []byte {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatalf("Error generating random AES key: %v", err)
	}
	return key
}

func EncryptAes256Gcm(key []byte, message []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return []byte(""), err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return []byte(""), err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return []byte(""), err
	}
	return gcm.Seal(nonce, nonce, message /*additionalData=*/, nil), nil
}

func DecryptAes256Gcm(key []byte, ciphertext []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return []byte(""), err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return []byte(""), err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return []byte(""), errors.New("Ciphertext smaller than nonce.")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return []byte(""), err
	}
	return plaintext, nil
}

// Generate an RSA encryption key pair, returned as a
// (publicKey, privateKey) tuple.
func GenerateRSAKeyPair() ([]byte, []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating RSA key pair: %v", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	publicKeyDer, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatalf("Error marshaling public key: %v", err)
	}
	return publicKeyDer, privateKeyBytes
}

// Takes a PEM-encoded X.509 certificate and parses it into an
// x509.Certificate object.
func ParsePemEncodedX509Cert(pemEncodedCert string) *x509.Certificate {
	// x509 only parses DER-encoded ASN.1 structures, so we need to
	// decode the PEM into DER first before we can parse it.
	block, _ := pem.Decode([]byte(pemEncodedCert))

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Error parsing certificate: %v", err)
	}
	return cert
}
