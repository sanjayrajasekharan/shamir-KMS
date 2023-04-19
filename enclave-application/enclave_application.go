package enclave

import (
	"crypto/x509"
	"log"

	vaultShamir "github.com/hashicorp/vault/shamir"
	"github.com/sanjayrajasekharan/shamir-KMS/certificates"
	cryptoutils "github.com/sanjayrajasekharan/shamir-KMS/crypto-utils"
)

type KeyType int

const (
	KeyTypeUnspecified KeyType = 0
	RSA                        = 1
	DSA                        = 2
	AES_256_GCM                = 3
)

// The enclave application's private key. Kept in enclave memory and used to
// decrypt received messages.
var privateKeyBytes []byte

// The enclave application's public key. Shared outside the enclave for clients
// to use for encrypting messages sent to the enclave.
var publicKeyDer []byte

// The KMS's root master key. Kept in enclave memory.
var rootMasterKey []byte

// The different shares of the root master key, held in an in-memory map of
// keyId -> operatorId -> share.
var rootMasterKeyShares = make(map[string]map[string][]byte)

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

// Calls GenerateAndSplitRootMasterKey with the following params:
//   - keyId: "rootMasterKey"
//   - keyType: AES_256_GCM
//   - k: 3
//   - operatorCertificates: each of the (parsed) certificates in
//     certificates/certificates.go
func GenerateAndSplitRootMasterKeyWithDefaultParams() {
	keyId := "rootMasterKey"
	k := 3
	var operatorCertificates []*x509.Certificate
	operatorCertificates = append(operatorCertificates, cryptoutils.ParsePemEncodedX509Cert(certificates.Operator1Cert))
	operatorCertificates = append(operatorCertificates, cryptoutils.ParsePemEncodedX509Cert(certificates.Operator2Cert))
	operatorCertificates = append(operatorCertificates, cryptoutils.ParsePemEncodedX509Cert(certificates.Operator3Cert))
	operatorCertificates = append(operatorCertificates, cryptoutils.ParsePemEncodedX509Cert(certificates.Operator4Cert))
	operatorCertificates = append(operatorCertificates, cryptoutils.ParsePemEncodedX509Cert(certificates.Operator5Cert))
	GenerateAndSplitRootMasterKey(keyId, AES_256_GCM, k, operatorCertificates)
}

// Return the root master key share for the specifeid key corresponding to the
// operator identified in `operatorCertPem`. Return an error if no root master
// key with ID `keyID` exists, or if there is no share corresponding to the
// operator identified in `operatorCertPem`
// TODO: Return error instead of logging and crashing
// TODO: encrypt share with operator's public key
func GetRootMasterKeyShare(keyID string, operatorCert *x509.Certificate) []byte {
	GenerateAndSplitRootMasterKeyWithDefaultParams()
	operatorIdToShareMap, exists := rootMasterKeyShares[keyID]
	if !exists {
		log.Fatalf("No known key with id: %s", keyID)
	}
	// TODO: Validate cert is signed by trusted CA
	operatorId := operatorCert.Subject.CommonName
	share, exists := operatorIdToShareMap[operatorId]
	if !exists {
		log.Fatalf("Operator identity not in share map: %s", operatorId)
	}
	return share
}

// Generates an AES key and splits it into n shares (where n is the length of `operatorCertificates`) such that
// the split secret can be reconstructed from `k` shares.
func GenerateAndSplitRootMasterKey(keyId string, keyType KeyType, k int, operatorCertificates []*x509.Certificate) {
	n := len(operatorCertificates)
	if n <= k {
		log.Fatalf("The number of supplied operator identities must be greater than k.")
	}
	// TODO: Decide which key type to generate based on `keyType`
	rootMasterKey = cryptoutils.GenerateAes256Key()
	shares, err := vaultShamir.Split(rootMasterKey, len(operatorCertificates), k)
	if err != nil {
		log.Fatalf("Error splitting key: %v", err)
	}
	var sharesMap = make(map[string][]byte)
	for i := 0; i < n; i++ {
		operatorCertificate := operatorCertificates[i]
		// TODO: Encrypt the share with the public key in the certificate
		sharesMap[operatorCertificate.Subject.CommonName] = shares[i]
	}
	rootMasterKeyShares[keyId] = sharesMap
}

// A placeholder function for returning the enclave's attestation document.
// Generates an ephemeral key pair and puts the public key in the document
// while keeping the private key in memory.
// Should eventually be updated to request an actual attestation document
// from the AWS Nitro Hypervisor.
func GetEnclaveAttestationDocument() enclaveAttestationDocument {
	publicKeyDer, privateKeyBytes = cryptoutils.GenerateRSAKeyPair()
	attestationDoc := enclaveAttestationDocument{
		PublicKey: publicKeyDer,
	}

	return attestationDoc
}
