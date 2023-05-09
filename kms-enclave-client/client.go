package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
)

type requestMessage struct {
	Operation string      `json:"operation"`
	Data      interface{} `json:"data"`
}

type responseMessage struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func sendRequest(conn net.Conn, req requestMessage) {
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(req); err != nil {
		fmt.Println("Failed to encode request:", err)
		return
	}

	// Read and print the response from the server
	decoder := json.NewDecoder(conn)
	var resp responseMessage
	if err := decoder.Decode(&resp); err != nil {
		fmt.Println("Failed to decode response:", err)
		return
	}

	fmt.Printf("Response: %+v\n", resp)
}

func main() {
	// Establish a VSOCK connection to the server
	conn, err := net.Dial("tcp", "localhost:5005")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to VSOCK server: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	certBytes, err := ioutil.ReadFile("./credentials/server-cert.pem")
	if err != nil {
		fmt.Println("Failed to read certificate file:", err)
		return
	}

	// Convert the certificate bytes to a string
	certString := string(certBytes)

	// Print the certificate contents to the console
	fmt.Println("Certificate contents:", certString)

	// Test generateRootMasterKey operation
	sendRequest(conn, requestMessage{
		Operation: "generateRootMasterKey",
		Data: map[string]interface{}{
			"keyType":       "AES",
			"keyID":         "test-key",
			"engineerCerts": []string{"credentials/server-cert.pem", "credentials/server-key.pem"}, // Use the same certificate twice for testing
			"k":             2,
		},
	})

	// Test getRootMasterKeyShare operation
	sendRequest(conn, requestMessage{
		Operation: "getRootMasterKeyShare",
		Data: map[string]interface{}{
			"keyID":         "test-key",
			"clientCertPEM": "client-cert-pem",
		},
	})

	// Test injectRootMasterKeyShare operation
	sendRequest(conn, requestMessage{
		Operation: "injectRootMasterKeyShare",
		Data: map[string]interface{}{
			"keyID":    "test-key",
			"keyShare": "sample-key-share",
		},
	})

	// Test getEnclaveAttestationDocument operation
	sendRequest(conn, requestMessage{
		Operation: "getEnclaveAttestationDocument",
	})

	// Test encryptWithRootMasterKey operation
	sendRequest(conn, requestMessage{
		Operation: "encryptWithRootMasterKey",
		Data: map[string]interface{}{
			"keyID":   "test-key",
			"message": "sample-message",
		},
	})

	// Test decryptWithRootMasterKey operation
	sendRequest(conn, requestMessage{
		Operation: "decryptWithRootMasterKey",
		Data: map[string]interface{}{
			"keyID":      "test-key",
			"ciphertext": "sample-ciphertext",
		},
	})
}
