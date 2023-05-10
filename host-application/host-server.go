package main

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mdlayher/vsock"
)

const (
	vsockCID  = 15   // Replace with the correct CID for the vsock connection
	vsockPort = 5005 // Replace with the correct port number for the vsock connection
	connTmo   = 5 * time.Second
)

type VsockStream struct {
	connTmo time.Duration
	sock    *vsock.Conn
}

func NewVsockStream(connTmo time.Duration) *VsockStream {
	return &VsockStream{
		connTmo: connTmo,
	}
}

func (v *VsockStream) Connect(cid, port uint32) error {
	conn, err := vsock.Dial(cid, port, nil)
	if err != nil {
		return err
	}
	v.sock = conn
	v.sock.SetDeadline(time.Now().Add(v.connTmo))
	return nil
}

func (v *VsockStream) SendData(data []byte) error {
	_, err := v.sock.Write(data)
	return err
}

func (v *VsockStream) RecvData() ([]byte, error) {
	var result []byte
	buf := make([]byte, 1024)
	for {
		n, err := v.sock.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		result = append(result, buf[:n]...)
	}
	return result, nil
}

func (v *VsockStream) Disconnect() {
	v.sock.Close()
}

func relayToVsock(c *gin.Context, requestData []byte) {
	client := NewVsockStream(connTmo)
	if err := client.Connect(vsockCID, vsockPort); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer client.Disconnect()

	if err := client.SendData(requestData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	responseData, err := client.RecvData()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Data(http.StatusOK, "application/json", responseData)
}

func main() {
	router := gin.Default()

	router.POST("/v1/keys/generate", func(c *gin.Context) {
		// Extract request data from c.Request.Body if needed
		requestData := []byte("generateRootMasterKey")
		relayToVsock(c, requestData)
	})

	router.GET("/v1/keys/share/:keyId", func(c *gin.Context) {
		keyId := c.Param("keyId")
		requestData := []byte(fmt.Sprintf("getRootMasterKeyShare:%s", keyId))
		relayToVsock(c, requestData)
	})

	router.POST("/v1/keys/inject", func(c *gin.Context) {
		// Extract request data from c.Request.Body if needed
		requestData := []byte("injectRootMasterKeyShare")
		relayToVsock(c, requestData)
	})

	router.GET("/v1/keys/attestationDoc", func(c *gin.Context) {
		requestData := []byte("getEnclaveAttestationDocument")
		relayToVsock(c, requestData)
	})

	router.POST("/v1/keys/encrypt", func(c *gin.Context) {
		// Extract request data from c.Request.Body if needed
		requestData := []byte("encryptWithRootMasterKey")
		relayToVsock(c, requestData)
	})

	router.POST("/v1/keys/decrypt", func(c *gin.Context) {
		// Extract request data from c.Request.Body if needed
		requestData := []byte("decryptWithRootMasterKey")
		relayToVsock(c, requestData)
	})

	router.Run() // Listen and serve on 0.0.0.0:8080 (for Windows "localhost:8080")
}
