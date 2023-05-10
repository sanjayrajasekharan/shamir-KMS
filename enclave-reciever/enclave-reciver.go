package main

import (
	"fmt"
	"log"

	"github.com/mdlayher/vsock"
)

func main() {

	listener, err := vsock.Listen(5005, nil)
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}

	defer listener.Close()

	fmt.Println("Listening on port 5005")

	for {
		// Accept incoming connection
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		// go handleConnection(conn)

		fmt.Printf("Type of conn: %T\n", conn)
	}

}

// func handleConnection (conn *vsock.Conn) {

// }
