package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func ProcessHttpResponse(resp *http.Response, err error) {
	if err != nil {
		switch e := err.(type) {
		case *url.Error:
			log.Fatalf("url.Error received on http request: %s", e)
		default:
			log.Fatalf("Unexpected error received: %s", err)
		}
	}

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		log.Fatalf("unexpected error reading response body: %s", err)
	}

	fmt.Printf("\nResponse from server: \n\tHTTP status: %s\n\tBody: %s\n", resp.Status, body)
}

func MakeGenerateRootMasterKeyRequest(client http.Client, serverAddress string, keyID string, keyType string, engineerCerts []string, k int) {
	postBody := map[string]any{"keyType": keyType, "keyID": keyID, "engineerCerts": engineerCerts, "k": k}
	postBodyJson, err := json.Marshal(postBody)
	resp, err := client.Post(fmt.Sprintf("https://%s/v1/keys/generate", serverAddress), "application/json", bytes.NewBuffer(postBodyJson))
	ProcessHttpResponse(resp, err)
}

func MakeGetRootMasterKeyShareRequest(client http.Client, serverAddress string, keyID string) {
	resp, err := client.Get(fmt.Sprintf("https://%s/v1/keys/share/%s", serverAddress, keyID))
	ProcessHttpResponse(resp, err)
}

func MakeInjectRootMasterKeyShareRequest(client http.Client, serverAddress string, keyID string, share string) {
	postBody := map[string]any{"keyID": keyID, "keyShare": share}
	postBodyJson, err := json.Marshal(postBody)
	resp, err := client.Post(fmt.Sprintf("https://%s/v1/keys/inject", serverAddress), "application/json", bytes.NewBuffer(postBodyJson))
	ProcessHttpResponse(resp, err)
}

func MakeEncryptRequest(client http.Client, serverAddress string, keyID string, message string) {
	postBody := map[string]any{"keyID": keyID, "message": message}
	postBodyJson, err := json.Marshal(postBody)
	resp, err := client.Post(fmt.Sprintf("https://%s/v1/keys/encrypt", serverAddress), "application/json", bytes.NewBuffer(postBodyJson))
	ProcessHttpResponse(resp, err)
}
func MakeDecryptRequest(client http.Client, serverAddress string, keyID string, ciphertext string) {
	postBody := map[string]any{"keyID": keyID, "ciphertext": ciphertext}
	postBodyJson, err := json.Marshal(postBody)
	resp, err := client.Post(fmt.Sprintf("https://%s/v1/keys/decrypt", serverAddress), "application/json", bytes.NewBuffer(postBodyJson))
	ProcessHttpResponse(resp, err)
}

func main() {
	// ********************************************** Parse flags
	help := flag.Bool("help", false, "Optional, prints usage info")
	srvhost := flag.String("srvhost", "localhost", "The server's host name")
	srvport := flag.String("srvport", "8080", "Required, the server's port.")
	caCertFile := flag.String("cacert", "", "Required, the name of the CA that signed the server's certificate")
	clientCertFile := flag.String("clientcert", "", "Required, the name of the client's certificate file")
	clientKeyFile := flag.String("clientkey", "", "Required, the file name of the clients's private key file")
	method := flag.String("method", "", "Required, the RPC being invoked on the server. Must be one of GenerateRootMasterKey, GetRootMasterKeyShare, InhectRootMasterKeyShare, Encrypt, Decrypt")
	// Args, expected depending on the RPC being invoked
	keyID := flag.String("keyid", "", "Optional")
	share := flag.String("share", "", "Optional")
	message := flag.String("message", "", "Optional")
	ciphertext := flag.String("ciphertext", "", "Optional")
	operatorCerts := flag.String("operatorcerts", "", "Optional. Comma separated list of filepaths to operator certificates")
	k := flag.Int("k", 0, "Optional.")
	keyType := flag.String("keytype", "", "Optional")
	flag.Parse()

	usage := `usage:
	
client -clientcert <clientCertificateFile> -cacert <caFile> -clientkey <clientPrivateKeyFile> [-host <srvHostName> -help]
	
Options:
  -help       Optional, Prints this message
  -srvhost    Optional, the server's hostname, defaults to 'localhost'
  -clientcert Optional, the name the clients's certificate file
  -clientkey  Optional, the name the client's key certificate file
  -cacert     Required, the name of the CA that signed the server's certificate
 `

	if *help == true {
		fmt.Println(usage)
		return
	}

	// ********************************************** Load credentials and create HTTP client
	if *caCertFile == "" {
		log.Fatalf("caCert is required but missing:\n%s", usage)
	}

	var cert tls.Certificate
	var err error
	if *clientCertFile != "" && *clientKeyFile != "" {
		cert, err = tls.LoadX509KeyPair(*clientCertFile, *clientKeyFile)
		if err != nil {
			log.Fatalf("Error creating x509 keypair from client cert file %s and client key file %s", *clientCertFile, *clientKeyFile)
		}
	}

	log.Printf("CAFile: %s", *caCertFile)
	caCert, err := ioutil.ReadFile(*caCertFile)
	if err != nil {
		log.Fatalf("Error opening cert file %s, Error: %s", *caCertFile, err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	t := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
		},
	}

	client := http.Client{Transport: t, Timeout: 15 * time.Second}
	serverAddress := fmt.Sprintf("%s:%s", *srvhost, *srvport)

	// ********************************************** Process command line and make request
	if *method == "GetRootMasterKeyShare" {
		MakeGetRootMasterKeyShareRequest(client, serverAddress, *keyID)
	} else if *method == "GenerateRootMasterKey" {
		MakeGenerateRootMasterKeyRequest(client, serverAddress, *keyID, *keyType, strings.Split(*operatorCerts, ","), *k)
	} else if *method == "InjectRootMasterKeyShare" {
		MakeInjectRootMasterKeyShareRequest(client, serverAddress, *keyID, *share)
	} else if *method == "Encrypt" {
		MakeEncryptRequest(client, serverAddress, *keyID, *message)
	} else if *method == "Decrypt" {
		MakeDecryptRequest(client, serverAddress, *keyID, *ciphertext)
	} else {
		log.Fatalf("Received request for unsupported RPC method: %s", *method)
	}
}
