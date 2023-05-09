package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	enclave "github.com/sanjayrajasekharan/shamir-KMS/enclave-application"
)

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

	fmt.Println("Received request:", req)

	if err := c.BindJSON(&req); err != nil {
		c.Error(err)
		return
	}

	fmt.Println("Received request:", req)

	var certificates []*x509.Certificate
	for _, cert := range req.EngineerCerts {
		parsedCert, err := x509.ParseCertificate([]byte(cert))
		if err != nil {
			c.Error(err)
		}
		certificates = append(certificates, parsedCert)
	}
	err := enclave.GenerateAndSplitRootMasterKey(req.KeyID, req.KeyType, req.K, certificates)
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

	share, err := enclave.GetRootMasterKeyShare(keyID, operatorCert)
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
	err := enclave.InjectRootMasterKeyShare(req.KeyID, req.KeyShare, c.Request.TLS.PeerCertificates[0])
	if err != nil {
		c.Error(err)
		return
	}

	c.IndentedJSON(http.StatusOK, gin.H{})
}

// Return the attestation document of this enclave,
// which includes the enclave's measurements and a
// public key whose corresponding private key is only
// known to the enclave.
func getEnclaveAttestationDocument(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"enclaveDoc": enclave.GetEnclaveAttestationDocument()})
}

// Encrypt the provided plaintext key with the
// specified root master key.
func encryptWithRootMasterKey(c *gin.Context) {
	// Parse the request body
	var req encryptWithRootMasterKeyRequest
	if err := c.BindJSON(&req); err != nil {
		return
	}
	ciphertext, err := enclave.EncryptWithRootMasterKey(req.Message, req.KeyID)
	if err != nil {
		c.Error(err)
		return
	}
	c.IndentedJSON(http.StatusOK, gin.H{"ciphertext": ciphertext})
}

// Decrypt the provided plaintext key with the
// specified root master key.
func decryptWithRootMasterKey(c *gin.Context) {
	// Parse the request body
	var req decryptWithRootMasterKeyRequest
	if err := c.BindJSON(&req); err != nil {
		return
	}
	plaintext, err := enclave.DecryptWithRootMasterKey(req.Ciphertext, req.KeyID)
	if err != nil {
		c.Error(err)
		return
	}
	c.IndentedJSON(http.StatusOK, gin.H{"plaintext": plaintext})
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

	// The certificate in credentials/server-cert.pem is a self-signed cert, so HTTPS
	// cURL requests to the server can set the `--cacert` flag to a file containing
	// the same contents as credentials/server-cert.pem.
	s.ListenAndServeTLS("credentials/server-cert.pem", "credentials/server-key.pem")
}
