package enclave

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log"

	vaultShamir "github.com/hashicorp/vault/shamir"
	"github.com/sanjayrajasekharan/shamir-KMS/certificates"
	cryptoutils "github.com/sanjayrajasekharan/shamir-KMS/crypto-utils"
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

type rootMasterKeyParamValues struct {
	N       int    `json:"n"`
	K       int    `json:"l"`
	KeyType string `json:"keyType"`
}

// A map from a root master key ID to the parameters configured for that key
var rootMasterKeyParams = make(map[string]rootMasterKeyParamValues)

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
	GenerateAndSplitRootMasterKey(keyId, "AES_256_GCM", k, operatorCertificates)
}

// Return the root master key share for the specifeid key corresponding to the
// operator identified in `operatorCertPem`. Return an error if no root master
// key with ID `keyID` exists, or if there is no share corresponding to the
// operator identified in `operatorCertPem`
// TODO: Return error instead of logging and crashing
// TODO: encrypt share with operator's public key
func GetRootMasterKeyShare(keyID string, operatorCert *x509.Certificate) ([]byte, error) {
	GenerateAndSplitRootMasterKeyWithDefaultParams()
	operatorIdToShareMap, exists := rootMasterKeyShares[keyID]
	if !exists {
		return []byte(""), errors.New(fmt.Sprintf("No known key with id: %s", keyID))
	}
	// TODO: Validate cert is signed by trusted CA
	operatorId := operatorCert.Subject.CommonName
	share, exists := operatorIdToShareMap[operatorId]
	if !exists {
		return []byte(""), errors.New(fmt.Sprintf("Operator identity not in share map: %s", operatorId))
	}
	// TODO: Encrypt share with operator public key
	return share, nil
}

// Generates a key of type `keyType` and splits it into n shares (where n is the length of `operatorCertificates`) such that
// the split secret can be reconstructed from `k` shares.
func GenerateAndSplitRootMasterKey(keyId string, keyType string, k int, operatorCertificates []*x509.Certificate) error {
	n := len(operatorCertificates)
	if n <= k {
		return errors.New("The number of supplied operator identities must be greater than k.")
	}
	if keyType == "AES_256_GCM" {
		rootMasterKey = cryptoutils.GenerateAes256Key()
	} else {
		return errors.New("Received generation request for unsupported key type")
	}

	shares, err := vaultShamir.Split(rootMasterKey, len(operatorCertificates), k)
	if err != nil {
		return err
	}
	var sharesMap = make(map[string][]byte)
	for i := 0; i < n; i++ {
		operatorCertificate := operatorCertificates[i]
		sharesMap[operatorCertificate.Subject.CommonName] = shares[i]
	}
	rootMasterKeyShares[keyId] = sharesMap
	rootMasterKeyParams[keyId] = rootMasterKeyParamValues{
		K:       k,
		N:       n,
		KeyType: keyType,
	}
	return nil
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

func EncryptWithRootMasterKey(message string, keyID string) (string, error) {
	GenerateAndSplitRootMasterKeyWithDefaultParams()
	// TODO: Look up the key to use from a map based on keyID
	key := rootMasterKey
	keyType := rootMasterKeyParams[keyID].KeyType
	if keyType == "AES_256_GCM" {
		return encryptWithRootMasterKeyAes256Gcm(message, key)
	} else {
		return "", errors.New(fmt.Sprintf("The specified root master key, %s, does not have a supported key type: %s", keyID, keyType))
	}
}

func DecryptWithRootMasterKey(message string, keyID string) (string, error) {
	GenerateAndSplitRootMasterKeyWithDefaultParams()
	// TODO: Look up the key to use from a map based on keyID
	key := rootMasterKey
	keyType := rootMasterKeyParams[keyID].KeyType
	if keyType == "AES_256_GCM" {
		return decryptWithRootMasterKeyAes256Gcm(message, key)
	} else {
		return "", errors.New(fmt.Sprintf("The specified root master key, %s, does not have a supported key type: %s", keyID, keyType))
	}
}

func encryptWithRootMasterKeyAes256Gcm(message string, rootMasterKey []byte) (string, error) {
	// TODO: Decrypt message using enclave private key (We assume
	// incoming messages that require confidentiality are encrypted
	// with the public key)
	messageBytes := []byte(message)
	ciphertextBytes, err := cryptoutils.EncryptAes256Gcm(rootMasterKey, messageBytes)
	return string(ciphertextBytes), err
}

func decryptWithRootMasterKeyAes256Gcm(ciphertext string, rootMasterKey []byte) (string, error) {
	// TODO: Do we need to encrypt a decrypt message with the enclave public key? Maybe it's easier to
	// just assume every incoming message is encrypted
	ciphertextBytes := []byte(ciphertext)
	plaintextBytes, err := cryptoutils.DecryptAes256Gcm(rootMasterKey, ciphertextBytes)
	return string(plaintextBytes), err
}

// TODO: Since this file is currently just a library, and not a separate application, it doesn't
// actually hold anything in memory. We should figure out how we want this to work for the non-enclave
// case (set up a separate Gin server?)
func InjectRootMasterKeyShare(keyID string, keyShare string, operatorCertificate *x509.Certificate) error {
	// TODO: Check that the operator identified by operatorCertificate is authorized to inject a key share
	// TODO: Decrypt keyShare with enclave private key
	if rootMasterKeyShares[keyID] == nil {
		rootMasterKeyShares[keyID] = make(map[string][]byte)
	}
	rootMasterKeyShares[keyID][operatorCertificate.Subject.CommonName] = []byte(keyShare)
	log.Printf("Stored share from operator \"%s\"", operatorCertificate.Subject.CommonName)
	shares := make([][]byte, 0, len(rootMasterKeyShares[keyID]))
	for operatorName := range rootMasterKeyShares[keyID] {
		shares = append(shares, rootMasterKeyShares[keyID][operatorName])
	}
	// Attempt to reconstruct the root master key if we have at least k shares
	if len(rootMasterKey) == 0 && len(shares) >= rootMasterKeyParams[keyID].K {
		log.Print("Attempting to reconstruct root master key...")
		combinedKey, err := vaultShamir.Combine(shares)
		if err != nil {
			return err
		}
		rootMasterKey = combinedKey
		log.Print("Successfully reconstructed root master key.")
	}
	return nil
}

// Operations the enclave application should perform on startup
func Startup() {
	// TODO: Implement
	//		1. Read root master key parameters from local file
	//		2. Generate private/public keypair
	//		3. Get attestation document
}
