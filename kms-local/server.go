package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	vaultShamir "github.com/hashicorp/vault/shamir"
	cryptoutils "github.com/sanjayrajasekharan/shamir-KMS/crypto-utils"
)

// ************************* Begin Enclave Code *****************************
// The enclave application's private key. Kept in enclave memory and used to
// decrypt received messages.
var privateKeyBytes []byte

// Same as above, but stored as an *rsa.PrivateKey
var privateKeyRsa *rsa.PrivateKey

// The enclave application's public key. Shared outside the enclave for clients
// to use for encrypting messages sent to the enclave.
var publicKeyDer []byte

// Same as above, but stored as an *rsa.PublicKey
var publicKeyRsa *rsa.PublicKey

// Map from keyID -> key material for each root master key held in memory.
var rootMasterKeyMap = make(map[string][]byte)

// The different shares of the root master key, held in an in-memory map of
// keyId -> operatorId -> share.
var rootMasterKeyShares = make(map[string]map[string][]byte)

var enableEncryption = true

type rootMasterKeyParamValues struct {
	N                   int      `json:"n"`
	K                   int      `json:"k"`
	KeyType             string   `json:"keyType"`
	AuthorizedOperators []string `json:"authorizedOperators"`
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

func contains(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func enclave_encryptWithRootMasterKeyAes256Gcm(message string, rootMasterKey []byte) (string, error) {
	// TODO: Decrypt message using enclave private key (We assume
	// incoming messages that require confidentiality are encrypted
	// with the public key)
	messageBytes := []byte(message)
	ciphertextBytes, err := cryptoutils.EncryptAes256Gcm(rootMasterKey, messageBytes)
	return string(ciphertextBytes), err
}

func enclave_decryptWithRootMasterKeyAes256Gcm(ciphertext string, rootMasterKey []byte) (string, error) {
	ciphertextBytes := []byte(ciphertext)
	plaintextBytes, err := cryptoutils.DecryptAes256Gcm(rootMasterKey, ciphertextBytes)
	return string(plaintextBytes), err
}

// Return the root master key share for the specified key corresponding to the
// operator identified in `operatorCertPem`. Return an error if no root master
// key with ID `keyID` exists, or if there is no share corresponding to the
// operator identified in `operatorCertPem`
func enclave_GetRootMasterKeyShare(keyID string, operatorCert *x509.Certificate) ([]byte, error) {
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
	operatorPublicKey := operatorCert.PublicKey.(*rsa.PublicKey)
	if enableEncryption {
		return cryptoutils.EncryptWithPublicKey(share, operatorPublicKey), nil
	}
	return share, nil
}

// Generates a key of type `keyType` and splits it into n shares (where n is the length of `operatorCertificates`) such that
// the split secret can be reconstructed from `k` shares.
func enclave_GenerateAndSplitRootMasterKey(keyId string, keyType string, k int, operatorCertificates []*x509.Certificate) error {
	n := len(operatorCertificates)
	if n <= k {
		return errors.New("The number of supplied operator identities must be greater than k.")
	}
	log.Printf("Received generation request with Shamir parameters n=%v, k=%v", n, k)
	var keyMaterial []byte
	if keyType == "AES_256_GCM" {
		keyMaterial = cryptoutils.GenerateAes256Key()
		rootMasterKeyMap[keyId] = keyMaterial
	} else {
		return errors.New("Received generation request for unsupported key type")
	}

	shares, err := vaultShamir.Split(keyMaterial, n, k)
	if err != nil {
		return err
	}
	var sharesMap = make(map[string][]byte)
	var authorizedOperators []string
	for i := 0; i < n; i++ {
		operatorCertificate := operatorCertificates[i]
		sharesMap[operatorCertificate.Subject.CommonName] = shares[i]
		authorizedOperators = append(authorizedOperators, operatorCertificate.Subject.CommonName)
	}
	rootMasterKeyShares[keyId] = sharesMap
	rootMasterKeyParams[keyId] = rootMasterKeyParamValues{
		K:                   k,
		N:                   n,
		KeyType:             keyType,
		AuthorizedOperators: authorizedOperators,
	}
	file, err := json.MarshalIndent(rootMasterKeyParams, "", " ")
	err = ioutil.WriteFile("key-params.json", file, 0644)
	if err != nil {
		log.Print("Error writing new prams to file.")
		return err
	}
	return nil
}

// A placeholder function for returning the enclave's attestation document.
// Generates an ephemeral key pair and puts the public key in the document
// while keeping the private key in memory.
// Should eventually be updated to request an actual attestation document
// from the AWS Nitro Hypervisor.
func enclave_GetEnclaveAttestationDocument() enclaveAttestationDocument {
	publicKeyDer, privateKeyBytes = cryptoutils.GenerateRSAKeyPair()
	attestationDoc := enclaveAttestationDocument{
		PublicKey: publicKeyDer,
	}

	return attestationDoc
}

func enclave_EncryptWithRootMasterKey(message string, keyID string) (string, error) {
	key := rootMasterKeyMap[keyID]
	keyType := rootMasterKeyParams[keyID].KeyType
	if enableEncryption {
		message = string(cryptoutils.DecryptWithPrivateKey([]byte(message), privateKeyRsa))
	}
	if keyType == "AES_256_GCM" {
		return enclave_encryptWithRootMasterKeyAes256Gcm(message, key)
	} else {
		return "", errors.New(fmt.Sprintf("The specified root master key, %s, does not have a supported key type: %s", keyID, keyType))
	}
}

func enclave_DecryptWithRootMasterKey(message string, keyID string, operatorCertificate *x509.Certificate) (string, error) {
	key := rootMasterKeyMap[keyID]
	keyType := rootMasterKeyParams[keyID].KeyType
	if keyType == "AES_256_GCM" {
		plaintext, err := enclave_decryptWithRootMasterKeyAes256Gcm(message, key)
		if !enableEncryption {
			return plaintext, err
		}
		wrappedPlaintext := cryptoutils.EncryptWithPublicKey([]byte(plaintext), operatorCertificate.PublicKey.(*rsa.PublicKey))
		return string(wrappedPlaintext), nil

	} else {
		return "", errors.New(fmt.Sprintf("The specified root master key, %s, does not have a supported key type: %s", keyID, keyType))
	}
}

func enclave_InjectRootMasterKeyShare(keyID string, keyShare string, operatorCertificate *x509.Certificate) error {
	params := rootMasterKeyParams[keyID]
	operatorCommonName := operatorCertificate.Subject.CommonName
	if !contains(operatorCommonName, params.AuthorizedOperators) {
		return errors.New(fmt.Sprintf("Operator %s is not authorized to inject a share for %s, Authorized operators are %v", operatorCommonName, keyID, params.AuthorizedOperators))
	}
	if rootMasterKeyShares[keyID] == nil {
		rootMasterKeyShares[keyID] = make(map[string][]byte)
	}
	if !enableEncryption {
		rootMasterKeyShares[keyID][operatorCommonName] = []byte(keyShare)
	} else {
		log.Printf("Key share bytes: %v", []byte(keyShare))
		log.Printf("Private key: %v", privateKeyRsa)
		rootMasterKeyShares[keyID][operatorCommonName] = cryptoutils.DecryptWithPrivateKey([]byte(keyShare), privateKeyRsa)
	}

	log.Printf("Stored share from operator \"%s\"", operatorCommonName)
	shares := make([][]byte, 0, len(rootMasterKeyShares[keyID]))
	for operatorName := range rootMasterKeyShares[keyID] {
		shares = append(shares, rootMasterKeyShares[keyID][operatorName])
	}
	log.Printf("Current shares: %v", shares)

	// Attempt to reconstruct the root master key if we have at least k shares
	if rootMasterKeyMap[keyID] == nil && len(shares) >= rootMasterKeyParams[keyID].K {
		log.Print("Attempting to reconstruct root master key...")
		log.Printf("Stored k is %v", rootMasterKeyParams[keyID].K)
		log.Printf("Len shares is %v", len(shares))
		log.Printf("hasRootMasterKey is %v", rootMasterKeyMap[keyID])
		combinedKey, err := vaultShamir.Combine(shares)
		if err != nil {
			return err
		}
		rootMasterKeyMap[keyID] = combinedKey
		log.Print("Successfully reconstructed root master key.")
	}
	return nil
}

// ************************* End Enclave Code *****************************

var keyMap = make(map[string]string)

type generateRootMasterKeyRequest struct {
	KeyType       string   `json:"keyType"`
	KeyID         string   `json:"keyID"`
	EngineerCerts []string `json:"engineerCerts"`
	K             int      `json:"k"`
}

type injectRootMasterKeyShareRequest struct {
	KeyID    string `json:"keyID"`
	KeyShare string `json:"keyShare"`
}

type encryptWithRootMasterKeyRequest struct {
	KeyID   string `json:"keyID"`
	Message string `json:"message"`
}

type decryptWithRootMasterKeyRequest struct {
	KeyID      string `json:"keyID"`
	Ciphertext string `json:"ciphertext"`
}

// Generate a root master key according to the arguments
// in the generateRootMasterKeyRequest specified in the
// request body. The generated key is split into n shares
// where n is the length of `engineerIDs` in the request,
// and can be reconstructed from `k` shares.
func generateRootMasterKey(c *gin.Context) {
	// Parse the request body
	var req generateRootMasterKeyRequest
	if err := c.BindJSON(&req); err != nil {
		c.Error(err)
		return
	}
	var certificates []*x509.Certificate
	for _, certFile := range req.EngineerCerts {
		pemData, err := os.ReadFile(certFile)
		parsedCert := cryptoutils.ParsePemEncodedX509Cert(string(pemData))
		if err != nil {
			c.Error(err)
		}
		certificates = append(certificates, parsedCert)
	}
	err := enclave_GenerateAndSplitRootMasterKey(req.KeyID, req.KeyType, req.K, certificates)
	if err != nil {
		c.Error(err)
	}
	c.IndentedJSON(http.StatusOK, gin.H{})

}

// Return a share of the specified root master key
// corresponding to the authorized caller.
func getRootMasterKeyShare(c *gin.Context) {
	// Parse the URL param
	keyID := c.Param("keyId")
	operatorCert := c.Request.TLS.PeerCertificates[0]

	share, err := enclave_GetRootMasterKeyShare(keyID, operatorCert)
	if err != nil {
		c.Error(err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"keyID": keyID, "share": share})

}

// Accept a share of the specified root master key.
func injectRootMasterKeyShare(c *gin.Context) {
	// Parse the request body
	var req injectRootMasterKeyShareRequest
	if err := c.BindJSON(&req); err != nil {
		return
	}
	err := enclave_InjectRootMasterKeyShare(req.KeyID, req.KeyShare, c.Request.TLS.PeerCertificates[0])
	if err != nil {
		c.Error(err)
		return
	}

	c.IndentedJSON(http.StatusOK, gin.H{})
}

// Return the attestation document of this enclave,
// which includes the enclave's measurements and a
// public key whose corresponding private key is only
// known to the enclave_
func getEnclaveAttestationDocument(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"enclaveDoc": enclave_GetEnclaveAttestationDocument()})
}

// Encrypt the provided plaintext key with the specified root master key.
func encryptWithRootMasterKey(c *gin.Context) {
	// Parse the request body
	var req encryptWithRootMasterKeyRequest
	if err := c.BindJSON(&req); err != nil {
		return
	}
	ciphertext, err := enclave_EncryptWithRootMasterKey(req.Message, req.KeyID)
	if err != nil {
		c.Error(err)
		return
	}
	c.IndentedJSON(http.StatusOK, gin.H{"ciphertext": ciphertext})
}

// Decrypt the provided plaintext key with the specified root master key.
func decryptWithRootMasterKey(c *gin.Context) {
	// Parse the request body
	var req decryptWithRootMasterKeyRequest
	if err := c.BindJSON(&req); err != nil {
		return
	}
	plaintext, err := enclave_DecryptWithRootMasterKey(req.Ciphertext, req.KeyID, c.Request.TLS.PeerCertificates[0])
	if err != nil {
		c.Error(err)
		return
	}
	c.IndentedJSON(http.StatusOK, gin.H{"plaintext": plaintext})
}

func getKeyParams() error {
	jsonFile, err := os.Open("key-params.json")
	if err != nil {
		return err
	}
	contents, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return err
	}
	json.Unmarshal(contents, &rootMasterKeyParams)
	log.Printf("Parsed root master key params: %v", rootMasterKeyParams)
	return nil
}

func loadKeyPrivateKey(keyFilePath string) error {
	privateKeyFile, err := os.Open(keyFilePath)
	if err != nil {
		return err
	}
	privateKeyPem, err := ioutil.ReadAll(privateKeyFile)
	block, _ := pem.Decode(privateKeyPem)
	privateKeyRsa, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		privateKeyRsa = parsedKey.(*rsa.PrivateKey)
	}
	privateKeyBytes = block.Bytes
	return nil
}

func loadPublicKey(certFilePath string) error {
	certFile, err := os.Open(certFilePath)
	if err != nil {
		return err
	}

	certPem, err := ioutil.ReadAll(certFile)
	block, _ := pem.Decode(certPem)
	cert, err := x509.ParseCertificate(block.Bytes)
	publicKeyRsa = cert.PublicKey.(*rsa.PublicKey)
	return nil
}

// Reads the server's public/private key pair from a local file and stores the key
// material in memory
func loadServerCredentials(certFilePath string, keyFilePath string) {
	err := loadKeyPrivateKey(keyFilePath)
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err.Error())
	}
	err = loadPublicKey(certFilePath)
	if err != nil {
		log.Fatalf("Failed to load public key: %v", err.Error())
	}
}

func main() {
	router := gin.Default()
	router.POST("/v1/keys/generate", generateRootMasterKey)
	router.GET("/v1/keys/share/:keyId", getRootMasterKeyShare)
	router.POST("/v1/keys/inject", injectRootMasterKeyShare)
	router.GET("/v1/keys/attestationDoc", getEnclaveAttestationDocument)
	router.POST("/v1/keys/encrypt", encryptWithRootMasterKey)
	router.POST("/v1/keys/decrypt", decryptWithRootMasterKey)

	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAnyClientCert,
	}

	s := http.Server{
		Addr:      "localhost:8080",
		Handler:   router,
		TLSConfig: tlsConfig,
	}

	loadServerCredentials("credentials/server-cert.pem", "credentials/server-key.pem")
	if getKeyParams() != nil {
		log.Printf("Error reading root master key parameter file. File may not exist.")
	}

	// The certificate in credentials/server-cert.pem is a self-signed cert, so HTTPS
	// cURL requests to the server can set the `--cacert` flag to a file containing
	// the same contents as credentials/server-cert.pem.
	s.ListenAndServeTLS("credentials/server-cert2.pem", "credentials/server-key2.pem")
}
