package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

var keyMap = make(map[string]string)

type generateRootMasterKeyRequest struct {
	KeyType     string   `json:"keyType"`
	KeyID       string   `json:"keyID"`
	EngineerIDs []string `json:"engineerIDs"`
	K           int      `json:"k"`
}

type injectRootMasterKeyShareRequest struct {
	KeyID    string `json:"keyID"`
	KeyShare string `json:"keyShare"`
}

type encryptWithRootMasterKeyRequest struct {
	KeyID        string `json:"keyID"`
	PlaintextKey string `json:"plaintextKey"`
}

type decryptWithRootMasterKeyRequest struct {
	KeyID        string `json:"keyID"`
	EncryptedKey string `json:"encryptedKey"`
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
		return
	}
	c.IndentedJSON(http.StatusOK, req)
}

// Return a share of the specified root master key
// corresponding to the authorized caller.
func getRootMasterKeyShare(c *gin.Context) {
	// Parse the URL param
	keyID := c.Param("keyId")
	c.JSON(http.StatusOK, gin.H{"keyID": keyID})
}

// Accept a share of the specified root master key.
func injectRootMasterKeyShare(c *gin.Context) {
	// Parse the request body
	var req injectRootMasterKeyShareRequest
	if err := c.BindJSON(&req); err != nil {
		return
	}

	c.IndentedJSON(http.StatusOK, req)
}

// Return the attestation document of this enclave,
// which includes the enclave's measurements and a
// public key whose corresponding private key is only
// known to the enclave.
func getEnclaveAttestationDocument(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{})
}

// Encrypt the provided plaintext key with the
// specified root master key.
func encryptWithRootMasterKey(c *gin.Context) {
	// Parse the request body
	var req encryptWithRootMasterKeyRequest
	if err := c.BindJSON(&req); err != nil {
		return
	}
	c.IndentedJSON(http.StatusOK, req)
}

// Decrypt the provided plaintext key with the
// specified root master key.
func decryptWithRootMasterKey(c *gin.Context) {
	// Parse the request body
	var req decryptWithRootMasterKeyRequest
	if err := c.BindJSON(&req); err != nil {
		return
	}
	c.IndentedJSON(http.StatusOK, req)
}

func main() {
	router := gin.Default()
	router.POST("/v1/keys/generate", generateRootMasterKey)
	router.GET("/v1/keys/share/:keyId", getRootMasterKeyShare)
	router.POST("/v1/keys/inject", injectRootMasterKeyShare)
	router.GET("/v1/keys/attestationDoc", getEnclaveAttestationDocument)
	router.POST("/v1/keys/encrypt", encryptWithRootMasterKey)
	router.POST("/v1/keys/decrypt", decryptWithRootMasterKey)

	router.Run("localhost:8080")
}
