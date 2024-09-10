package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	// Get the hostname of the node
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Printf("Error getting hostname: %v\n", err)
		return
	}

	for {
		// Print the hostname
		fmt.Printf("Agent core deployed on Node: %s\n", hostname)
		time.Sleep(5 * time.Second)
	}
}
