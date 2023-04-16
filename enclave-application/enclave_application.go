package enclave

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"log"
)

var privateKeyBytes []byte
var publicKeyDer []byte

// Based on this specification:
// https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html#doc-def
// Should eventually be replaced by some definition specified in some AWS code
// library (I'm assuming such a thing exists).
type enclaveAttestationDocument struct {
	ModuleID    string         `json:"modeulID"`
	Timestamp   uint8          `json:"timestamp"`
	Digest      string         `json:"digest"`
	PCRs        map[int]string `json:"pcrs"`
	Certificate string         `json:"certificate"`
	CABundle    []string       `json:"cabundle"`
	// optional DER-encoded key the attstation consumer
	// can use to encrypt data with
	PublicKey []byte `json:"publicKey"`
}

// Generate an RSA encryption key pair held in enclave memory for the
// lifetime of the enclave application.
func generateRSAKeyPair() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating RSA key pair: %v", err)
	}

	privateKeyBytes = x509.MarshalPKCS1PrivateKey(privateKey)

	publicKeyDer, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatalf("Error marshaling public key: %v", err)
	}
}

// A placeholder function for returning the enclave's attestation document.
// Should eventually be updated to request an actual attestation document
// from the AWS Nitro Hypervisor.
func GetEnclaveAttestationDocument() enclaveAttestationDocument {
	generateRSAKeyPair()
	attestationDoc := enclaveAttestationDocument{
		PublicKey: publicKeyDer,
	}

	return attestationDoc
}
