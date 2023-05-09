package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"

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
type requestMessage struct {
	Operation string      `json:"operation"`
	Data      interface{} `json:"data"`
}

type responseMessage struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type getRootMasterKeyShareRequest struct {
	KeyID         string `json:"keyID"`
	ClientCertPEM string `json:"clientCertPEM"` // Client certificate in PEM format
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read the request message from the client
	decoder := json.NewDecoder(conn)
	var req requestMessage
	if err := decoder.Decode(&req); err != nil {
		sendErrorResponse(conn, "Failed to decode request: "+err.Error())
		return
	}

	// Process the request based on the operation
	switch req.Operation {
	case "generateRootMasterKey":
		// Parse the request data and call the appropriate handler
		data, _ := json.Marshal(req.Data)
		var genReq generateRootMasterKeyRequest
		if err := json.Unmarshal(data, &genReq); err != nil {
			sendErrorResponse(conn, "Failed to parse request data: "+err.Error())
			return
		}

		fmt.Println("Received request:", genReq)

		// Generate and split the root master key
		var certificates []*x509.Certificate
		for _, cert := range genReq.EngineerCerts {

			// Decode the PEM-encoded certificate string
			certBlock, _ := pem.Decode([]byte(cert))
			if certBlock == nil {
				sendErrorResponse(conn, "Failed to decode PEM block")
				return
			}

			parsedCert, err := x509.ParseCertificate([]byte(cert))
			if err != nil {
				sendErrorResponse(conn, "Failed to parse certificate: "+err.Error())
				return
			}
			certificates = append(certificates, parsedCert)
		}
		err := enclave.GenerateAndSplitRootMasterKey(genReq.KeyID, genReq.KeyType, genReq.K, certificates)
		if err != nil {
			sendErrorResponse(conn, "Failed to generate and split root master key: "+err.Error())
			return
		}

		// Send a success response to the client
		resp := responseMessage{
			Status:  "success",
			Message: "Root master key generated and split successfully",
		}
		encoder := json.NewEncoder(conn)
		encoder.Encode(resp)

	case "getRootMasterKeyShare":
		// Parse the request data and call the appropriate handler
		data, _ := json.Marshal(req.Data)
		var getReq getRootMasterKeyShareRequest
		if err := json.Unmarshal(data, &getReq); err != nil {
			sendErrorResponse(conn, "Failed to parse request data: "+err.Error())
			return
		}
		// Parse the client certificate from the PEM string
		clientCertBlock, _ := pem.Decode([]byte(getReq.ClientCertPEM))
		if clientCertBlock == nil {
			sendErrorResponse(conn, "Failed to parse client certificate: invalid PEM format")
			return
		}
		clientCert, err := x509.ParseCertificate(clientCertBlock.Bytes)
		if err != nil {
			sendErrorResponse(conn, "Failed to parse client certificate: "+err.Error())
			return
		}
		// Call the handler for getRootMasterKeyShare
		share, err := enclave.GetRootMasterKeyShare(getReq.KeyID, clientCert) // Assuming this function returns a share
		if err != nil {
			sendErrorResponse(conn, "Failed to get root master key share: "+err.Error())
			return
		}
		sendSuccessResponse(conn, "Root master key share retrieved successfully", map[string]string{"keyID": getReq.KeyID, "share": string(share)})

	case "injectRootMasterKeyShare":
		// Parse the request data and call the appropriate handler
		data, _ := json.Marshal(req.Data)
		var injReq injectRootMasterKeyShareRequest
		if err := json.Unmarshal(data, &injReq); err != nil {
			sendErrorResponse(conn, "Failed to parse request data: "+err.Error())
			return
		}
		// Call the handler for injectRootMasterKeyShare
		err := enclave.InjectRootMasterKeyShare(injReq.KeyID, injReq.KeyShare, nil) // Assuming no client certificate
		if err != nil {
			sendErrorResponse(conn, "Failed to inject root master key share: "+err.Error())
			return
		}
		sendSuccessResponse(conn, "Root master key share injected successfully", nil)

	case "getEnclaveAttestationDocument":
		// Call the handler for getEnclaveAttestationDocument
		enclaveDoc := enclave.GetEnclaveAttestationDocument()
		sendSuccessResponse(conn, "Enclave attestation document retrieved successfully", enclaveDoc)

	case "encryptWithRootMasterKey":
		// Parse the request data and call the appropriate handler
		data, _ := json.Marshal(req.Data)
		var encReq encryptWithRootMasterKeyRequest
		if err := json.Unmarshal(data, &encReq); err != nil {
			sendErrorResponse(conn, "Failed to parse request data: "+err.Error())
			return
		}
		// Call the handler for encryptWithRootMasterKey
		ciphertext, err := enclave.EncryptWithRootMasterKey(encReq.Message, encReq.KeyID)
		if err != nil {
			sendErrorResponse(conn, "Failed to encrypt with root master key: "+err.Error())
			return
		}
		sendSuccessResponse(conn, "Encryption with root master key successful", map[string]string{"ciphertext": ciphertext})

	case "decryptWithRootMasterKey":
		// Parse the request data and call the appropriate handler
		data, _ := json.Marshal(req.Data)
		var decReq decryptWithRootMasterKeyRequest
		if err := json.Unmarshal(data, &decReq); err != nil {
			sendErrorResponse(conn, "Failed to parse request data: "+err.Error())
			return
		}
		// Call the handler for decryptWithRootMasterKey
		plaintext, err := enclave.DecryptWithRootMasterKey(decReq.Ciphertext, decReq.KeyID)
		if err != nil {
			sendErrorResponse(conn, "Failed to decrypt with root master key: "+err.Error())
			return
		}
		sendSuccessResponse(conn, "Decryption with root master key successful", map[string]string{"plaintext": plaintext})

	default:
		// Unknown operation
		sendErrorResponse(conn, "Unknown operation: "+req.Operation)
		return
	}

	// Send the response back to the client (implementation omitted for brevity)
	// ...
}

func sendSuccessResponse(conn net.Conn, message string, data interface{}) {
	resp := responseMessage{
		Status:  "success",
		Message: message,
		Data:    data,
	}
	encoder := json.NewEncoder(conn)
	encoder.Encode(resp)
}

func sendErrorResponse(conn net.Conn, message string) {
	resp := responseMessage{
		Status:  "error",
		Message: message,
	}
	encoder := json.NewEncoder(conn)
	encoder.Encode(resp)
}

func main() {
	// Create a VSOCK socket
	listener, err := net.Listen("tcp", "localhost:5005")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create VSOCK listener: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Println("VSOCK server listening on port 5005")

	// Listen for incoming connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to accept connection: %v\n", err)
			continue
		}

		// Handle the connection in a separate goroutine
		go handleConnection(conn)
	}
}
