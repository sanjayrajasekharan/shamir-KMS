package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mdlayher/vsock"
)

const (
	vsockCID  = 15   // Replace with the correct CID for the vsock connection
	vsockPort = 5005 // Replace with the correct port number for the vsock connection
)

func relayToVsock(c *gin.Context, requestData []byte) {
	conn, err := vsock.Dial(vsockCID, vsockPort, nil)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer conn.Close()

	_, err = conn.Write(requestData)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	response := make([]byte, 1024)
	n, err := conn.Read(response)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Data(http.StatusOK, "application/json", response[:n])
}

func main() {
	router := gin.Default()

	router.POST("/v1/keys/generate", func(c *gin.Context) {
		requestData := []byte("generateRootMasterKey")
		relayToVsock(c, requestData)
	})

	router.GET("/v1/keys/share/:keyId", func(c *gin.Context) {
		keyId := c.Param("keyId")
		requestData := []byte(fmt.Sprintf("getRootMasterKeyShare:%s", keyId))
		relayToVsock(c, requestData)
	})

	router.POST("/v1/keys/inject", func(c *gin.Context) {
		requestData := []byte("injectRootMasterKeyShare")
		relayToVsock(c, requestData)
	})

	router.GET("/v1/keys/attestationDoc", func(c *gin.Context) {
		requestData := []byte("getEnclaveAttestationDocument")
		relayToVsock(c, requestData)
	})

	router.POST("/v1/keys/encrypt", func(c *gin.Context) {
		requestData := []byte("encryptWithRootMasterKey")
		relayToVsock(c, requestData)
	})

	router.POST("/v1/keys/decrypt", func(c *gin.Context) {
		requestData := []byte("decryptWithRootMasterKey")
		relayToVsock(c, requestData)
	})
	router.Run() // Listen and serve on 0.0.0.0:8080 (for Windows "localhost:8080")
}
